#!/usr/bin/env python3
"""
Optional fallback through Syft (github.com/anchore/syft) for what cra-kit's
own parsers do not cover: Go, Rust, .NET, Ruby, OS packages, binaries, and
the contents of a container image.

cra-kit's own parsers stay authoritative for Gradle/Maven, PyPI, npm and
Composer: they know which dependencies actually ship (dev and build-only
configurations are excluded), and `license_enrich.py` resolves Gradle
licences offline from the local cache, which Syft cannot do. So for any
ecosystem where our parsers produced components, Syft's directory-scan
components of that ecosystem are dropped, and any remaining duplicate keeps
our record.

Offline by design:
  - Syft's update check is switched off (SYFT_CHECK_FOR_APP_UPDATE=false).
  - An image is read only from a local archive or directory, or from a
    local daemon when the caller names one explicitly (`docker:`/`podman:`).
    Pulling from a registry is refused: the tool does not add network access
    beyond the OSV lookup it already has.

Never required. Without Syft, the gaps are recorded as known unknowns.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

GENERATOR_PROP = "cra:generator"

# Schemes Syft accepts that stay on this machine.
LOCAL_IMAGE_SCHEMES = {"docker-archive", "oci-archive", "oci-dir", "docker", "podman", "dir"}
REFUSED_IMAGE_SCHEMES = {"registry"}

# purl type -> cra:ecosystem label for components Syft found
ECOSYSTEM_BY_PURL_TYPE = {
    "maven": "maven",
    "golang": "go",
    "cargo": "cargo",
    "nuget": "nuget",
    "npm": "npm",
    "pypi": "pypi",
    "composer": "composer",
    "gem": "gem",
    "swift": "swift",
    "cocoapods": "cocoapods",
    "pub": "pub",
    "deb": "os:deb",
    "rpm": "os:rpm",
    "apk": "os:apk",
    "alpm": "os:alpm",
    "github": "github-action",
    "generic": "binary",
}

TIMEOUT_SECONDS = 600


class SyftError(RuntimeError):
    """A Syft run that cannot be trusted. Never fatal to the SBOM build."""


def find_syft(explicit: str | Path | None = None) -> str | None:
    """Path to the Syft binary: `explicit` if given (must exist), else the
    first `syft` on PATH, else None."""
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        found = shutil.which(str(explicit))
        return found
    return shutil.which("syft")


def image_source(arg: str) -> str:
    """Turn --syft-image into a Syft source string that stays local.

    An existing directory is an OCI layout; an existing file is a
    `docker save` archive. An explicit local scheme is passed through.
    Anything else — a bare image reference, or `registry:` — is refused,
    because Syft would resolve it from a registry over the network.
    """
    scheme, sep, rest = arg.partition(":")
    # "D:\\images\\x.tar" — a Windows drive letter, not a scheme
    is_scheme = bool(sep) and len(scheme) > 1 and re.fullmatch(r"[a-z-]+", scheme)
    if is_scheme:
        if scheme in REFUSED_IMAGE_SCHEMES:
            raise SyftError(
                "pulling an image from a registry is not supported (no new "
                "network access); docker save the image and pass the archive"
            )
        if scheme in LOCAL_IMAGE_SCHEMES:
            return arg
    p = Path(arg)
    if p.is_dir():
        return f"oci-dir:{p}"
    if p.is_file():
        return f"docker-archive:{p}"
    raise SyftError(
        f"{arg!r} is not a local image archive or directory; a bare image "
        "reference would be pulled from a registry, which is not supported. "
        "docker save the image and pass the .tar, or name a local daemon "
        "explicitly (docker:<image>)"
    )


def run(syft: str, source: str, runner=subprocess.run) -> dict:
    """Run `syft scan <source> -o cyclonedx-json` and return the parsed
    document. `runner` is injectable so tests never need a real Syft."""
    env = dict(os.environ)
    env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    cmd = [syft, "scan", source, "-o", "cyclonedx-json", "--quiet"]
    try:
        r = runner(cmd, capture_output=True, text=True, env=env, timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as e:
        raise SyftError(f"could not run {syft}: {e}") from e
    if r.returncode != 0:
        tail = (r.stderr or "").strip().splitlines()
        raise SyftError(
            f"syft exited {r.returncode}" + (f": {tail[-1]}" if tail else "")
        )
    try:
        doc = json.loads(r.stdout)
    except ValueError as e:
        raise SyftError(f"syft output is not JSON: {e}") from e
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise SyftError("syft output is not a CycloneDX document")
    return doc


# --------------------------------------------------------------------------
# normalisation
# --------------------------------------------------------------------------

def purl_type(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0].lower()


def _normalise_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def dedupe_key(c: dict) -> tuple:
    """Identity for merging: ecosystem, group, name, version — the
    group:name@version of the brief, kept per ecosystem so that an npm and a
    PyPI package of the same name and version are not collapsed.

    Taken from the purl when there is one (qualifiers and subpath dropped:
    Syft adds `?type=jar` and the like where ours does not).
    """
    purl = c.get("purl")
    if purl and purl.startswith("pkg:"):
        body = purl[4:].split("#", 1)[0].split("?", 1)[0]
        ptype, _, rest = body.partition("/")
        path, _, version = rest.rpartition("@")
        if not path:  # no version in purl
            path, version = rest, ""
        ns, _, name = path.rpartition("/")
        ptype = ptype.lower()
        if ptype == "pypi":
            name = _normalise_pypi(name)
        elif ptype in {"npm", "maven", "composer", "golang", "cargo", "nuget"}:
            ns, name = ns.lower(), name.lower()
        return (ptype, ns, name, version)
    return ("", (c.get("group") or "").lower(), (c.get("name") or "").lower(),
            c.get("version") or "")


_KEEP = ("type", "group", "name", "version", "purl", "cpe", "licenses",
         "hashes", "externalReferences", "supplier", "author", "description")


def normalise(component: dict, source_kind: str) -> dict:
    """A Syft component reduced to the fields this kit uses, tagged with
    cra:generator=syft and the cra:* properties that build.py and
    vuln_scan.py read. Syft's own syft:* properties are dropped: they
    describe Syft's catalogue run, not the product."""
    c = {k: component[k] for k in _KEEP if k in component}
    c.setdefault("type", "library")
    if c.get("group") and c.get("name") and purl_type(c.get("purl")) == "maven":
        # match the display convention of our own Gradle components
        c["name"] = f"{c.pop('group')}:{c['name']}"
    c["bom-ref"] = c.get("purl") or f"syft:{c.get('name')}@{c.get('version', '')}"
    ptype = purl_type(c.get("purl"))
    eco = ECOSYSTEM_BY_PURL_TYPE.get(ptype or "", ptype or "unknown")
    c["properties"] = [
        {"name": "cra:ecosystem", "value": eco},
        # Syft does not tell direct from transitive, or shipped from dev.
        {"name": "cra:direct", "value": "unknown"},
        {"name": "cra:dev", "value": "unknown"},
        {"name": GENERATOR_PROP, "value": "syft"},
        {"name": "cra:syft-source", "value": source_kind},
    ]
    return c


def components_from(doc: dict, source_kind: str) -> list[dict]:
    return [
        normalise(c, source_kind)
        for c in doc.get("components", []) or []
        if isinstance(c, dict) and c.get("name")
        # Syft lists the scanned source itself (type file/container/
        # operating-system) alongside the packages; only packages belong here.
        and c.get("type") not in {"file", "operating-system"}
    ]


def merge(ours: list[dict], syft_dir: list[dict], syft_image: list[dict]) -> list[dict]:
    """One component list. Ours first and unchanged. From a directory scan,
    Syft components are dropped for every purl type our parsers already
    produced (ours know what ships; Syft would re-add dev dependencies and
    unpinned declarations). From an image scan they are kept — that is what
    is really inside the shipped container — unless the same
    group:name@version is already there."""
    our_types = {purl_type(c.get("purl")) for c in ours} - {None}
    seen = {dedupe_key(c) for c in ours}
    out = list(ours)
    for c in syft_dir:
        if purl_type(c.get("purl")) in our_types:
            continue
        k = dedupe_key(c)
        if k not in seen:
            seen.add(k)
            out.append(c)
    for c in syft_image:
        k = dedupe_key(c)
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out
