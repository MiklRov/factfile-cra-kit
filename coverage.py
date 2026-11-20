#!/usr/bin/env python3
"""
Coverage accounting for the SBOM: what was found in the source tree, what was
resolved into components, and what was not.

A bill of materials that silently leaves out a whole ecosystem looks exactly
like a complete one. ENISA's Technical Advisory on SBOM asks manufacturers to
"document known gaps, exceptions and known unknowns in SBOM coverage". This
module produces that record — the `known_unknowns` block — so that a gap
stops the reader, not the build.

Each entry says:
  ecosystem   which ecosystem was detected (go, cargo, container, ...)
  status      "unresolved" (no components at all) or "partial" (components
              present, but the transitive closure was not resolved)
  evidence    the files that show the ecosystem is there, relative to the root
  reason      why it was not resolved, in one sentence
  fix         the command or flag that resolves it
  base_images (containers only) the images named in FROM lines — the image is
              named even when its contents are not enumerated

Detection only reads file names and Dockerfile FROM lines. It never runs a
package manager and never touches the network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Directories that hold build output, vendored code or tool caches. Their
# manifests are not the product's own and would only produce false positives.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "build", "dist", "out",
    "target", ".gradle", ".idea", ".vscode", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "bin", "obj", "Pods",
    ".dart_tool", ".next", ".nuxt", "coverage",
}

MAX_DEPTH = 4

# ecosystem -> (exact file names, glob suffixes)
MARKERS: dict[str, tuple[set[str], tuple[str, ...]]] = {
    "gradle": ({"build.gradle", "build.gradle.kts"}, ()),
    "maven": ({"pom.xml"}, ()),
    "pypi": (
        {"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
         "uv.lock", "setup.py"},
        (),
    ),
    "npm": ({"package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml"}, ()),
    "composer": ({"composer.lock", "composer.json"}, ()),
    "go": ({"go.mod"}, ()),
    "cargo": ({"Cargo.toml", "Cargo.lock"}, ()),
    "nuget": (
        {"packages.config", "packages.lock.json", "Directory.Packages.props"},
        (".csproj", ".fsproj", ".vbproj"),
    ),
    "gem": ({"Gemfile.lock"}, ()),
    "swift": ({"Package.resolved"}, ()),
    "cocoapods": ({"Podfile.lock"}, ()),
    "pub": ({"pubspec.lock"}, ()),
    "container": ({"Dockerfile", "Containerfile"}, (".Dockerfile", ".dockerfile")),
}

# Which purl types count as "this ecosystem has components in the SBOM".
PURL_TYPES: dict[str, set[str]] = {
    "gradle": {"maven"},
    "maven": {"maven"},
    "pypi": {"pypi"},
    "npm": {"npm"},
    "composer": {"composer"},
    "go": {"golang"},
    "cargo": {"cargo"},
    "nuget": {"nuget"},
    "gem": {"gem"},
    "swift": {"swift"},
    "cocoapods": {"cocoapods"},
    "pub": {"pub"},
}

# Ecosystems this kit parses itself. Everything else needs Syft.
OWN_PARSERS = {"gradle", "pypi", "npm", "composer"}

SYFT_FIX = "install Syft (github.com/anchore/syft) and re-run, or pass --syft PATH"
IMAGE_FIX = (
    "on the build machine: docker save <image> -o image.tar, then re-run "
    "with --syft PATH --syft-image image.tar"
)


def detect(root: Path, max_depth: int = MAX_DEPTH) -> dict[str, list[str]]:
    """Walk `root` (to `max_depth` levels) and return
    {ecosystem: [relative posix paths of marker files]}, sorted.
    """
    found: dict[str, list[str]] = {}

    def visit(d: Path, depth: int) -> None:
        try:
            entries = sorted(d.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for p in entries:
            if p.is_dir():
                if depth < max_depth and p.name not in SKIP_DIRS:
                    visit(p, depth + 1)
                continue
            for eco, (names, suffixes) in MARKERS.items():
                if p.name in names or (suffixes and p.name.endswith(suffixes)):
                    found.setdefault(eco, []).append(
                        p.relative_to(root).as_posix()
                    )
    visit(root, 0)
    return {k: sorted(v) for k, v in sorted(found.items())}


# --------------------------------------------------------------------------
# Dockerfile FROM lines
# --------------------------------------------------------------------------

_FROM = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?\s*$",
    re.IGNORECASE,
)


def base_images(dockerfile: Path) -> list[str]:
    """Image references named in FROM lines, in order, without duplicates.

    Skipped: `scratch` (no base at all) and references to an earlier build
    stage by its alias — those are not images pulled from anywhere. An
    unexpanded `${ARG}` is kept verbatim: it is still more than nothing, and
    the reader can see the tag was parameterised.
    """
    try:
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    # join line continuations
    text = re.sub(r"\\\r?\n", " ", text)
    aliases: set[str] = set()
    out: list[str] = []
    for line in text.splitlines():
        m = _FROM.match(line)
        if not m:
            continue
        image = m.group("image")
        if image.lower() != "scratch" and image.lower() not in aliases and image not in out:
            out.append(image)
        if m.group("alias"):
            aliases.add(m.group("alias").lower())
    return out


# --------------------------------------------------------------------------
# the known-unknowns record
# --------------------------------------------------------------------------

def _purl_type(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0].lower()


def _props(c: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in c.get("properties", []) or []}


def known_unknowns(
    root: Path,
    components: list[dict],
    *,
    detected: dict[str, list[str]] | None = None,
    syft_dir_status: str | None = None,
    syft_image_status: str | None = None,
    gradle_tree: Path | None = None,
    pip_freeze: Path | None = None,
) -> list[dict]:
    """Compare what was detected with what ended up in `components`.

    `syft_dir_status` / `syft_image_status`: None when that Syft scan was not
    attempted, "ok" when it succeeded, otherwise a one-line reason it failed.
    """
    if detected is None:
        detected = detect(root)

    present_types = {_purl_type(c.get("purl")) for c in components}
    eco_props = {_props(c).get("cra:ecosystem") for c in components}

    out: list[dict] = []
    for eco, evidence in detected.items():
        if eco == "container":
            entry = _container_entry(root, evidence, syft_image_status)
            if entry:
                out.append(entry)
            continue

        has = bool(PURL_TYPES.get(eco, set()) & present_types) or eco in eco_props
        if has:
            partial = _partial_entry(eco, evidence, components, gradle_tree, pip_freeze)
            if partial:
                out.append(partial)
            continue

        if eco in OWN_PARSERS:
            reason, fix = _own_parser_gap(eco, evidence)
        elif syft_dir_status is None:
            reason = "no parser in cra-kit for this ecosystem, and Syft was not run"
            fix = SYFT_FIX
        elif syft_dir_status == "ok":
            reason = "Syft ran but catalogued no components for it"
            fix = "check the manifests are complete (lock files committed) and re-run"
        else:
            reason = f"Syft failed: {syft_dir_status}"
            fix = "fix the Syft error above and re-run"
        out.append({
            "ecosystem": eco,
            "status": "unresolved",
            "evidence": evidence,
            "reason": reason,
            "fix": fix,
        })
    return out


def _own_parser_gap(eco: str, evidence: list[str]) -> tuple[str, str]:
    at_root = [e for e in evidence if "/" not in e]
    if eco == "npm":
        if not any(e.endswith("package-lock.json") for e in evidence):
            return (
                "no package-lock.json (v2+) — cra-kit reads only that lock file; "
                "yarn.lock and pnpm-lock.yaml need Syft",
                "commit package-lock.json, or " + SYFT_FIX,
            )
    if eco == "composer":
        if not any(e.endswith("composer.lock") for e in evidence):
            return (
                "composer.json without composer.lock — versions are not pinned",
                "run composer install and commit composer.lock",
            )
    if not at_root:
        return (
            "the manifests are in subdirectories; cra-kit's own parser reads "
            "only the root (and modules named in settings.gradle)",
            "re-run with the subdirectory as root, pass the file explicitly "
            "(--pypi for requirements.txt), or " + SYFT_FIX,
        )
    return (
        "manifests found but no components could be read from them "
        "(unpinned or unsupported format)",
        SYFT_FIX,
    )


def _partial_entry(
    eco: str,
    evidence: list[str],
    components: list[dict],
    gradle_tree: Path | None,
    pip_freeze: Path | None,
) -> dict | None:
    """Components present, but only the declared top level."""
    if eco == "pypi" and pip_freeze is None:
        declared = [
            c for c in components
            if _props(c).get("cra:pypi-source") == "declared"
        ]
        if declared:
            return {
                "ecosystem": "pypi",
                "status": "partial",
                "evidence": evidence,
                "reason": (
                    f"{len(declared)} package(s) from requirements.txt only — "
                    "declared top-level packages, not the installed closure"
                ),
                "fix": (
                    "pip freeze > freeze.txt inside the real target "
                    "environment, then re-run with --pip-freeze freeze.txt"
                ),
            }
    if eco == "gradle" and gradle_tree is None:
        gradle = [c for c in components if _props(c).get("cra:ecosystem") == "gradle"]
        if gradle and all(_props(c).get("cra:direct") == "true" for c in gradle):
            return {
                "ecosystem": "gradle",
                "status": "partial",
                "evidence": evidence,
                "reason": (
                    f"{len(gradle)} component(s) from static parsing of build "
                    "files — transitive dependencies not resolved"
                ),
                "fix": (
                    "gradlew :<module>:dependencies --configuration <config> > "
                    "deps.txt, then re-run with --gradle-tree deps.txt"
                ),
            }
    return None


def _container_entry(
    root: Path, evidence: list[str], syft_image_status: str | None
) -> dict | None:
    if syft_image_status == "ok":
        return None
    images: list[str] = []
    for rel in evidence:
        for img in base_images(root / rel):
            if img not in images:
                images.append(img)
    if syft_image_status is None:
        reason = "a Dockerfile is a recipe, not an image — the built image was not scanned"
    else:
        reason = f"image scan failed: {syft_image_status}"
    return {
        "ecosystem": "container",
        "status": "unresolved",
        "evidence": evidence,
        "reason": reason,
        "fix": IMAGE_FIX,
        "base_images": images,
    }


# --------------------------------------------------------------------------
# serialisation into / out of the CycloneDX document
# --------------------------------------------------------------------------

PROP_RECORDED = "cra:coverage-recorded"
PROP_UNKNOWN = "cra:known-unknown"


def to_properties(entries: list[dict]) -> list[dict]:
    """CycloneDX has no field for coverage gaps, so the record lives in
    metadata.properties: one marker saying the record exists (so "no gaps
    recorded" is distinguishable from "nobody checked"), then one JSON-valued
    property per gap."""
    props = [{"name": PROP_RECORDED, "value": "true"}]
    for e in entries:
        props.append({
            "name": PROP_UNKNOWN,
            "value": json.dumps(e, ensure_ascii=False, sort_keys=True),
        })
    return props


def from_bom(bom: dict) -> list[dict] | None:
    """The known-unknowns record from an SBOM: None when the SBOM carries no
    record at all (another tool, or an older cra-kit), [] when it was checked
    and nothing is missing."""
    props = (bom.get("metadata") or {}).get("properties") or []
    if not any(p.get("name") == PROP_RECORDED for p in props):
        return None
    out = []
    for p in props:
        if p.get("name") != PROP_UNKNOWN:
            continue
        try:
            out.append(json.loads(p["value"]))
        except (ValueError, KeyError, TypeError):
            out.append({"ecosystem": "?", "status": "unresolved",
                        "reason": str(p.get("value")), "evidence": [], "fix": ""})
    return out
