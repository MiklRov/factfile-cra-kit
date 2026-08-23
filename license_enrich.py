#!/usr/bin/env python3
"""
Enrich a CycloneDX SBOM (output of sbom_gen.py) with resolved licenses for
its Gradle/Maven and Python components.

This is a port of an earlier internal collect_licenses.py into
cra-kit's SBOM-first pipeline: instead of parsing a Gradle dependency-tree
text file and a requirements.txt directly and emitting its own licenses.json,
this script reads an already-generated sbom.cdx.json, resolves a license for
each of its Gradle and Python components, and writes the licenses back onto
the SBOM's own component objects (CycloneDX `licenses` + `cra:license-*`
properties) so the enriched document stays a single, self-contained artefact.

GRADLE / MAVEN — three sources, tried in order, each one only consulted when
the previous one came up empty for a component:

  1. The local Gradle module cache (~/.gradle/caches/modules-2/files-2.1),
     which exists on any machine that has actually built the product. When a
     POM has no <licenses> block of its own but does have a <parent>, the
     parent POM is walked recursively (capped at 3 hops) — this is the single
     most common reason a component looks license-less at first glance.
  2. A network fetch of the POM (XML metadata only — never a .jar/.aar) from
     the appropriate Maven repository, cached to disk under
     --maven-fetch-cache so a re-run never re-fetches. This covers the large
     share of components whose local Gradle cache holds only a downloaded
     .aar/.jar with no adjacent .pom — Gradle resolved them via Gradle Module
     Metadata (a `.module` file elsewhere in the cache), which this tool does
     not parse; the POM is still there on the origin repository, just not
     mirrored into files-2.1. androidx.* / com.google.android.* /
     com.android.* groups are routed to Google's Maven repo
     (dl.google.com/dl/android/maven2/); everything else to Maven Central
     (repo1.maven.org/maven2/) — with a fallback attempt at the other
     repository if the primary one 404s. **On by default** (matching the
     reference tool this was ported from, scripts/collect_licenses.py in the
     earlier tooling) — pass --offline to disable it and stay strictly
     local, mirroring the spirit of --offline-python on the PyPI side.
  3. When neither the local cache nor the network has a POM at all, the
     component's own cached .aar/.jar (local cache only — this step never
     downloads an artifact, only ever reads one Gradle already fetched) is
     opened as a zip and searched for an embedded META-INF/maven/**/pom.xml
     (parsed the same way as a regular POM), then a Bundle-License header in
     META-INF/MANIFEST.MF (the OSGi convention). Genuinely last-resort: only
     reached when both the cache and network POM lookups failed outright.

PYTHON — PyPI JSON API (metadata only, no package download/execution),
skippable with --offline-python.

THREE OUTCOMES PER COMPONENT — never collapsed into two:
  1. resolved   -- >=1 license string found and mapped to a known SPDX id.
                   `licenses: [{"license": {"id": "<spdx>"}}]`,
                   cra:license-status=resolved.
  2. unmatched   -- a license string WAS found (in a POM, an archive, or PyPI
                   metadata) but does not map to any known SPDX identifier.
                   The raw text is preserved verbatim as `licenses:
                   [{"license": {"name": "<raw text>"}}]` -- CycloneDX's own
                   escape hatch for a real, specific, non-SPDX license (e.g.
                   "Play Core Software Development Kit Terms of Service").
                   This is NEVER represented the same way as outcome 3: a
                   real license with no SPDX id is not the same fact as no
                   license data existing at all, and a customer reading the
                   SBOM needs to see that exact text, not "unknown".
                   cra:license-status=unmatched (or "partial" if a dual
                   license had one matched and one unmatched entry).
  3. none        -- no license text ended up on the component, for one of two
                   very different reasons -- see cra:license-source below.
                   No `licenses` key is written at all (or an existing empty
                   one is removed) -- an absent/empty `licenses` field is
                   reserved for this state and this state only.
                   cra:license-status=none.

Every enriched component also gets `cra:license-source`, recording exactly
where the claim came from. **This is the fix for a real failure mode**: an
earlier version of this tool collapsed every "nothing found" case into a
single `none` source, which reads to a customer exactly like "you have a
legal problem" -- indistinguishable from a component that was actually
checked and confirmed to declare no license. The six values below keep those
apart:
  pom:gradle-cache      -- found directly on the component's own POM in the
                           local Gradle cache
  pom:parent            -- found on a POM reached via one or more <parent>
                           hops (from either the local cache or the network)
  pom:fetched           -- the component's own POM was not in any local
                           cache; found after a network fetch
  archive:manifest       -- found by opening the component's .jar/.aar itself
                           (embedded pom.xml or MANIFEST.MF Bundle-License)
  none:not-declared      -- a real, findable source (a POM, a POM reached via
                           a fully-walked parent chain, or an archive) WAS
                           read successfully, and it genuinely declares no
                           license. This is a fact about the component.
  unknown:not-determined -- no source could be found or read at all (missing
                           from the cache, not fetchable over the network,
                           no usable archive, a parse error, --offline with
                           nothing local, PyPI metadata absent/errored, or
                           --offline-python). This is a gap in *our* data,
                           not a statement about the component -- never treat
                           it as "no license".

Re-running this script on an already-enriched SBOM is safe: it replaces its
own cra:license-* properties rather than accumulating duplicates.

Usage:
    python3 license_enrich.py --sbom out/sbom.cdx.json \\
        --gradle-cache ~/.gradle/caches/modules-2/files-2.1 \\
        --requirements requirements.txt \\
        -o out/sbom.enriched.cdx.json

    # disable the Gradle-side network POM fetch, stay strictly local
    python3 license_enrich.py --sbom out/sbom.cdx.json --offline

    # skip PyPI network lookups
    python3 license_enrich.py --sbom out/sbom.cdx.json --offline-python

Default output path is non-destructive: "<name>.cdx.json" becomes
"<name>.enriched.cdx.json" alongside the input. Pass --in-place to overwrite
--sbom directly instead.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

TOOL_NAME = "cra-kit-license-enrich"
TOOL_VERSION = "0.1.0"

DEFAULT_GRADLE_CACHE = Path.home() / ".gradle" / "caches" / "modules-2" / "files-2.1"
DEFAULT_MAVEN_FETCH_CACHE = Path("maven-fetch-cache")

# Gradle-side network POM fetch (Part 1b): androidx.* / com.google.android.* /
# com.android.* groups are routed to Google's Maven repo first (these are
# frequently absent from Maven Central entirely); everything else to Maven
# Central first. Either way, the *other* repo is tried as a fallback before
# giving up -- mirrors the reference tool this was ported from
# (an earlier internal collect_licenses.py).
MAVEN_GOOGLE_REPO = "https://dl.google.com/dl/android/maven2/"
MAVEN_CENTRAL_REPO = "https://repo1.maven.org/maven2/"
GOOGLE_REPO_GROUP_PREFIXES = ("androidx.", "com.google.android.", "com.android.")

XML_NS_RE = re.compile(r"\{[^}]*\}")


def strip_ns(tag: str) -> str:
    return XML_NS_RE.sub("", tag)


# --------------------------------------------------------------------------
# Part 1: locate + parse POMs from the local Gradle cache (offline only)
# --------------------------------------------------------------------------

def find_pom(cache_root: Path, group: str, artifact: str, version: str) -> Path | None:
    """files-2.1/{group}/{artifact}/{version}/{sha1}/{artifact}-{version}.pom"""
    version_dir = cache_root / group / artifact / version
    if not version_dir.is_dir():
        return None
    target_name = f"{artifact}-{version}.pom"
    try:
        for hash_dir in version_dir.iterdir():
            if not hash_dir.is_dir():
                continue
            candidate = hash_dir / target_name
            if candidate.is_file():
                return candidate
            # fall back: any *.pom in this hash dir
            for f in hash_dir.glob("*.pom"):
                return f
    except OSError:
        return None
    return None


def find_artifact_archive(cache_root: Path, group: str, artifact: str, version: str) -> Path | None:
    """files-2.1/{group}/{artifact}/{version}/{sha1}/{artifact}-{version}.{aar,jar}

    Local Gradle cache only -- this never downloads an artifact, it only ever
    looks at a .jar/.aar Gradle already fetched for a real build. Used as the
    input to the archive-fallback path (Part 1c), which is why it is never
    given a network counterpart the way find_pom() is."""
    version_dir = cache_root / group / artifact / version
    if not version_dir.is_dir():
        return None
    try:
        for hash_dir in version_dir.iterdir():
            if not hash_dir.is_dir():
                continue
            for ext in ("aar", "jar"):
                candidate = hash_dir / f"{artifact}-{version}.{ext}"
                if candidate.is_file():
                    return candidate
            for ext in ("aar", "jar"):
                for f in hash_dir.glob(f"*.{ext}"):
                    return f
    except OSError:
        return None
    return None


def _repo_base_for_group(group: str) -> str:
    if group.startswith(GOOGLE_REPO_GROUP_PREFIXES):
        return MAVEN_GOOGLE_REPO
    return MAVEN_CENTRAL_REPO


def fetch_pom_network(fetch_cache_root: Path, group: str, artifact: str, version: str,
                       timeout: int = 10) -> tuple[Path | None, str | None]:
    """
    Read-only metadata fetch (POM XML only, never a jar/aar) for a GAV not
    found in the local Gradle cache. Tries the repo matching `group`'s prefix
    first (see GOOGLE_REPO_GROUP_PREFIXES), then the other one as a fallback.
    Saves whatever it fetches under fetch_cache_root, mirroring the layout
    used by scripts/collect_licenses.py's --maven-fetch-cache in the
    earlier tooling, so a re-run reuses it instead of re-fetching.

    Returns (path_to_cached_pom, error). A previously-fetched POM already
    sitting in the cache is reused without any network call at all.
    """
    dest_dir = fetch_cache_root / group / artifact / version
    dest_path = dest_dir / f"{artifact}-{version}.pom"
    if dest_path.is_file():
        return dest_path, None

    primary = _repo_base_for_group(group)
    other = MAVEN_CENTRAL_REPO if primary == MAVEN_GOOGLE_REPO else MAVEN_GOOGLE_REPO

    errors: list[str] = []
    for base in (primary, other):
        url = f"{base}{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
        except urllib.error.HTTPError as e:
            errors.append(f"HTTP {e.code} for {url}")
            continue
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            errors.append(f"{e} for {url}")
            continue

        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(data)
        return dest_path, None

    return None, "; ".join(errors)


_EMBEDDED_POM_RE = re.compile(r"^META-INF/maven/.+/pom\.xml$")
_BUNDLE_LICENSE_RE = re.compile(r"^Bundle-License:\s*(.+)$", re.MULTILINE)


def _unfold_manifest(text: str) -> str:
    """JAR MANIFEST.MF wraps long header values onto continuation lines that
    start with a single space (the manifest spec's 72-byte line limit). Undo
    that so a header value split across lines can still be matched by a
    single-line regex."""
    lines = text.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    for line in lines:
        if line.startswith(" ") and out:
            out[-1] += line[1:]
        else:
            out.append(line)
    return "\n".join(out)


def resolve_from_archive(archive_path: Path) -> dict:
    """
    Last-resort offline fallback (Part 1c): open the component's own
    .jar/.aar as a zip (both formats are zip files) and look for, in order:
      1. an embedded META-INF/maven/**/pom.xml -- some artifacts bundle a
         copy of their own POM; parsed the same way as a regular POM.
      2. a Bundle-License header in META-INF/MANIFEST.MF -- the OSGi
         convention for declaring a license in plain manifest text.
    A standard, well-known technique -- not specific to any tool.

    Returns {"licenses": [...], "outcome": "found"|"not-found", "note": str}.
    An archive that opens fine but has neither is "not-found", not a
    confirmed empty declaration: unlike an actual Maven POM, most jars don't
    carry license metadata at all even when the artifact is genuinely
    licensed, so its absence here is not good evidence of "no license".
    """
    try:
        with zipfile.ZipFile(archive_path) as zf:
            names = zf.namelist()

            for name in names:
                if not _EMBEDDED_POM_RE.match(name):
                    continue
                try:
                    raw = zf.read(name)
                except (KeyError, zipfile.BadZipFile, OSError):
                    continue
                licenses, _parent, err = _parse_pom_bytes(raw)
                if licenses and not err:
                    return {"licenses": licenses, "outcome": "found",
                            "note": f"embedded POM {name} in {archive_path.name}"}

            if "META-INF/MANIFEST.MF" in names:
                try:
                    manifest_text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
                except (KeyError, OSError):
                    manifest_text = ""
                m = _BUNDLE_LICENSE_RE.search(_unfold_manifest(manifest_text))
                if m:
                    raw_license = m.group(1).strip()
                    return {"licenses": [{"name": raw_license, "url": None}], "outcome": "found",
                            "note": f"Bundle-License header in {archive_path.name}"}

            return {"licenses": [], "outcome": "not-found",
                    "note": f"{archive_path.name} opened, no embedded POM license or "
                            f"Bundle-License header found"}
    except (zipfile.BadZipFile, OSError) as e:
        return {"licenses": [], "outcome": "not-found", "note": f"could not open {archive_path.name}: {e}"}


def _parse_pom_bytes(raw: bytes) -> tuple[list[dict], dict | None, str | None]:
    """Returns (licenses:list[{name,url}], parent:dict|None, error:str|None).
    Shared by parse_pom() (reads from the local cache or a network-fetched
    file) and resolve_from_archive() (reads an embedded pom.xml from a zip)."""
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, UnicodeDecodeError) as e:
        return [], None, f"XML parse error: {e}"

    licenses: list[dict] = []
    parent: dict | None = None
    for child in root:
        tag = strip_ns(child.tag)
        if tag == "licenses":
            for lic in child:
                if strip_ns(lic.tag) != "license":
                    continue
                name, url = None, None
                for f in lic:
                    ftag = strip_ns(f.tag)
                    if ftag == "name":
                        name = (f.text or "").strip()
                    elif ftag == "url":
                        url = (f.text or "").strip()
                if name or url:
                    licenses.append({"name": name, "url": url})
        elif tag == "parent":
            g, a, v = None, None, None
            for f in child:
                ftag = strip_ns(f.tag)
                if ftag == "groupId":
                    g = (f.text or "").strip()
                elif ftag == "artifactId":
                    a = (f.text or "").strip()
                elif ftag == "version":
                    v = (f.text or "").strip()
            if g and a and v:
                parent = {"group": g, "artifact": a, "version": v}
    return licenses, parent, None


def parse_pom(pom_path: Path) -> tuple[list[dict], dict | None, str | None]:
    """Returns (licenses:list[{name,url}], parent:dict|None, error:str|None)."""
    try:
        raw = pom_path.read_bytes()
    except OSError as e:
        return [], None, f"XML parse error: {e}"
    return _parse_pom_bytes(raw)


def resolve_license(cache_root: Path, group: str, artifact: str, version: str,
                     network_enabled: bool = True,
                     maven_fetch_cache: Path | None = None,
                     max_depth: int = 3) -> dict:
    """
    Walk POM -> parent POM chain until a <licenses> block is found, a POM is
    read successfully with nothing to find (a real, confirmed "no license"),
    or the chain runs out / can't be read at some hop (inconclusive). Each
    hop is looked for in the local Gradle cache first; when network_enabled
    is True (the default) and a hop's POM isn't in the local cache, it is
    fetched over the network via fetch_pom_network() and cached to disk under
    maven_fetch_cache. Parent recursion is capped at max_depth=3.

    Returns {"licenses": [...], "trail": [...], "source": str|None, "depth":
    int|None, "outcome": "found" | "declared-empty" | "not-found"}:
      - "found"          -- licenses is non-empty. "source" is one of
                             pom:gradle-cache / pom:fetched (depth 0, by
                             which of the two the winning POM came from) or
                             pom:parent (depth > 0, any hop's origin).
      - "declared-empty" -- every hop up to and including the last one was
                             read successfully (no missing POM, no parse
                             error, no cycle), and the last one has no
                             <licenses> and no <parent> -- a real POM
                             genuinely declaring no license, not a lookup
                             failure. Caller maps this to cra:license-source
                             "none:not-declared".
      - "not-found"      -- some hop could not be read at all (not in the
                             cache and not fetchable, a parse error, a cycle,
                             or max_depth exceeded before the chain
                             naturally terminated). Caller maps this to
                             "unknown:not-determined" (pending the archive
                             fallback, which is not attempted by this
                             function -- see enrich_gradle_component()).
    """
    if network_enabled and maven_fetch_cache is None:
        maven_fetch_cache = DEFAULT_MAVEN_FETCH_CACHE

    trail: list[dict] = []
    visited: set[tuple[str, str, str]] = set()
    g, a, v = group, artifact, version

    for depth in range(max_depth):
        gav = (g, a, v)
        if gav in visited:
            trail.append({"group": g, "artifact": a, "version": v,
                           "pom_path": None, "status": "cycle-detected", "hop_source": None})
            return {"licenses": [], "trail": trail, "outcome": "not-found", "source": None, "depth": None}
        visited.add(gav)

        pom_path = find_pom(cache_root, g, a, v)
        hop_source = "cache" if pom_path is not None else None

        if pom_path is None and network_enabled:
            fetched_path, fetch_err = fetch_pom_network(maven_fetch_cache, g, a, v)
            if fetched_path is not None:
                pom_path = fetched_path
                hop_source = "network"
            elif fetch_err:
                trail.append({"group": g, "artifact": a, "version": v, "pom_path": None,
                               "status": f"pom-not-in-cache; network-fetch-failed: {fetch_err}",
                               "hop_source": None})
                return {"licenses": [], "trail": trail, "outcome": "not-found", "source": None, "depth": None}

        if pom_path is None:
            status = "pom-not-in-cache" + ("" if network_enabled else " (network fetch disabled: --offline)")
            trail.append({"group": g, "artifact": a, "version": v, "pom_path": None,
                           "status": status, "hop_source": None})
            return {"licenses": [], "trail": trail, "outcome": "not-found", "source": None, "depth": None}

        licenses, parent, err = parse_pom(pom_path)
        if err:
            trail.append({"group": g, "artifact": a, "version": v, "pom_path": str(pom_path),
                           "status": f"parse-error: {err}", "hop_source": hop_source})
            return {"licenses": [], "trail": trail, "outcome": "not-found", "source": None, "depth": None}

        if licenses:
            trail.append({"group": g, "artifact": a, "version": v, "pom_path": str(pom_path),
                           "status": "licenses-found", "hop_source": hop_source})
            if depth == 0:
                source = "pom:gradle-cache" if hop_source == "cache" else "pom:fetched"
            else:
                source = "pom:parent"
            return {"licenses": licenses, "trail": trail, "outcome": "found", "source": source, "depth": depth}

        if parent:
            trail.append({"group": g, "artifact": a, "version": v, "pom_path": str(pom_path),
                           "status": "no-licenses-block, has parent", "hop_source": hop_source})
            g, a, v = parent["group"], parent["artifact"], parent["version"]
            continue

        trail.append({"group": g, "artifact": a, "version": v, "pom_path": str(pom_path),
                       "status": "no-licenses-block, no parent", "hop_source": hop_source})
        return {"licenses": [], "trail": trail, "outcome": "declared-empty", "source": None, "depth": depth}

    trail.append({"group": g, "artifact": a, "version": v, "pom_path": None,
                   "status": f"max recursion depth ({max_depth}) reached", "hop_source": None})
    return {"licenses": [], "trail": trail, "outcome": "not-found", "source": None, "depth": None}


# --------------------------------------------------------------------------
# Part 2: SPDX normalization -- ported as-is from collect_licenses.py
# --------------------------------------------------------------------------

def _norm_key(s: str) -> str:
    return re.sub(r"[\s,]+", " ", s.strip().lower()).strip(" .")


_SPDX_TABLE_RAW = {
    "the apache software license, version 2.0": "Apache-2.0",
    "the apache software license version 2.0": "Apache-2.0",
    "apache software license, version 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license v2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "the apache license, version 2.0": "Apache-2.0",
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit": "MIT",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause",
    "the 3-clause bsd license": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "the bsd license": "BSD-2-Clause",
    "bsd license": "BSD-2-Clause",
    "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license v1.0": "EPL-1.0",
    "epl-1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    "eclipse public license v2.0": "EPL-2.0",
    "epl-2.0": "EPL-2.0",
    "eclipse distribution license - v 1.0": "BSD-3-Clause",
    "eclipse distribution license v. 1.0": "BSD-3-Clause",
    "gnu lesser general public license": None,  # version-dependent, handled specially
    "lgpl": None,
    "gnu lesser general public license, version 2.1": "LGPL-2.1-or-later",
    "lgpl 2.1": "LGPL-2.1-or-later",
    "lgpl-2.1": "LGPL-2.1-or-later",
    "gnu lesser general public license v2.1 or later": "LGPL-2.1-or-later",
    "gnu lesser general public license v2.1": "LGPL-2.1-only",
    "gnu lesser general public license, version 3": "LGPL-3.0-or-later",
    "lgpl 3.0": "LGPL-3.0-or-later",
    "lgpl-3.0": "LGPL-3.0-or-later",
    "gnu general public license, version 2": "GPL-2.0-only",
    "gnu general public license v2.0": "GPL-2.0-only",
    "gpl 2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gnu general public license, version 2, with the classpath exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "gpl2 w/ classpath exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "gnu general public license, version 3": "GPL-3.0-only",
    "gpl 3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gnu affero general public license": None,
    "agpl": None,
    "gnu affero general public license, version 3": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "mozilla public license 1.1": "MPL-1.1",
    "mpl 1.1": "MPL-1.1",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license, version 2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "common development and distribution license": "CDDL-1.0",
    "cddl 1.0": "CDDL-1.0",
    "cddl+gpl license": "CDDL-1.0 OR GPL-2.0-only",
    "cddl/gplv2+ce": "CDDL-1.0 OR (GPL-2.0-only WITH Classpath-exception-2.0)",
    "cddl 1.1": "CDDL-1.1",
    "the sax license": "SAX-PD",
    "the w3c license": "W3C",
    "public domain": "LicenseRef-public-domain",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "wtfpl": "WTFPL",
    "cc0 1.0 universal": "CC0-1.0",
    "cc0": "CC0-1.0",
    "isc": "ISC",
    "the isc license": "ISC",
    "python software foundation license": "PSF-2.0",
    "bouncy castle licence": "MIT",
    "android software development kit license": "LicenseRef-android-sdk",
    "mit-cmu": "MIT-CMU",
    "cmu license": "MIT-CMU",
}

_LGPL_VERSION_RE = re.compile(r"lgpl[^0-9]{0,15}(\d+(?:\.\d+)?)")
_GPL_VERSION_RE = re.compile(r"(?<!l)gpl[^0-9]{0,15}(\d+(?:\.\d+)?)")
# "agpl" OR the spelled-out "affero [general public license|gpl]" (e.g. pymupdf's
# PyPI license field: "GNU AFFERO GPL 3.0") - both must be caught, this is the
# single most consequential misclassification for a proprietary app.
_AGPL_VERSION_RE = re.compile(r"(?:agpl|affero[^0-9]{0,30}gpl|affero[^0-9]{0,40}general public license)[^0-9]{0,15}(\d+(?:\.\d+)?)")
_OR_LATER_RE = re.compile(r"or (any )?later|or greater|\+\s*$|-or-later")
_ONLY_RE = re.compile(r"\bonly\b")


def normalize_spdx(raw_name: str) -> tuple[str | None, bool]:
    """Returns (spdx_id or None, matched:bool). Never invents an id: if
    nothing matches, returns (None, False) and the raw string is what the
    caller must preserve."""
    if not raw_name:
        return None, False
    key = _norm_key(raw_name)
    if key in _SPDX_TABLE_RAW and _SPDX_TABLE_RAW[key]:
        return _SPDX_TABLE_RAW[key], True

    lower = raw_name.lower()

    m = _AGPL_VERSION_RE.search(lower)
    if m:
        ver = m.group(1)
        suffix = "-or-later" if (_OR_LATER_RE.search(lower) or not _ONLY_RE.search(lower)) else "-only"
        return f"AGPL-{ver}{suffix}", True

    m = _LGPL_VERSION_RE.search(lower)
    if m:
        ver = m.group(1)
        suffix = "-only" if _ONLY_RE.search(lower) else "-or-later"
        return f"LGPL-{ver}{suffix}", True

    m = _GPL_VERSION_RE.search(lower)
    if m:
        ver = m.group(1)
        suffix = "-only" if _ONLY_RE.search(lower) else "-or-later"
        return f"GPL-{ver}{suffix}", True

    if "apache" in lower and "2" in lower:
        return "Apache-2.0", True
    if lower.strip() in ("mit", "the mit license", "mit license"):
        return "MIT", True

    return None, False


# --------------------------------------------------------------------------
# Part 3: Python / PyPI metadata (network, skippable via --offline-python)
# --------------------------------------------------------------------------

REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==|>=|~=)?\s*([^\s#]*)"
)


def parse_requirements(path: Path) -> list[dict]:
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = REQ_LINE_RE.match(line)
        if not m:
            continue
        name, extras, op, version = m.groups()
        out.append({
            "name": name,
            "extras": extras or "",
            "op": op or "",
            "version": version or "",
            "pinned": op == "==",
        })
    return out


def fetch_pypi_metadata(name: str, version: str | None, pinned: bool, timeout: int = 10) -> dict:
    """Returns dict with license info or error, via PyPI JSON API (metadata only)."""
    try:
        if pinned and version:
            url = f"https://pypi.org/pypi/{name}/{version}/json"
        else:
            url = f"https://pypi.org/pypi/{name}/json"
        req = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        info = data.get("info", {})
        resolved_version = info.get("version")
        license_field = (info.get("license") or "").strip()
        license_expression = (info.get("license_expression") or "").strip()
        classifiers = [c for c in info.get("classifiers", []) if c.startswith("License")]
        return {
            "resolved_version": resolved_version,
            "license_field": license_field or None,
            "license_expression": license_expression or None,
            "classifiers": classifiers,
            "error": None,
        }
    except urllib.error.HTTPError as e:
        return {"resolved_version": None, "license_field": None, "license_expression": None,
                "classifiers": [], "error": f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"resolved_version": None, "license_field": None, "license_expression": None,
                "classifiers": [], "error": str(e)}


CLASSIFIER_SPDX = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: Public Domain": "LicenseRef-public-domain",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)": "EPL-1.0",
}


def resolve_python_license(name: str, version: str | None, pinned: bool, offline: bool) -> dict:
    """Returns {"licenses": [{"raw","spdx","url","source"}], "note": str|None,
    "none_source": str}. "source" on an individual license entry is always
    "pypi:metadata" for entries actually found via PyPI; "none_source" is
    what the caller uses for cra:license-source when the list ends up empty
    -- "unknown:not-determined" when PyPI was never actually consulted
    (offline mode) or the lookup itself failed, versus "none:not-declared"
    when PyPI metadata WAS retrieved successfully and it simply has no
    License field or classifier. These are not the same fact and must not
    share a source value."""
    if offline:
        return {"licenses": [], "note": "offline mode: PyPI lookup skipped (--offline-python)",
                "none_source": "unknown:not-determined"}

    meta = fetch_pypi_metadata(name, version, pinned)
    if meta["error"]:
        return {"licenses": [], "note": f"PyPI metadata fetch failed: {meta['error']}",
                "none_source": "unknown:not-determined"}

    licenses: list[dict] = []
    seen_spdx: set[str] = set()

    # PEP 639 license-expression: already a valid SPDX expression (may be
    # compound, e.g. "Apache-2.0 OR BSD-3-Clause") - use as-is.
    if meta.get("license_expression"):
        licenses.append({
            "raw": meta["license_expression"], "spdx": meta["license_expression"],
            "url": None, "source": "pypi:metadata", "expression": True,
        })
        seen_spdx.add(meta["license_expression"])

    for c in meta["classifiers"]:
        spdx = CLASSIFIER_SPDX.get(c)
        if spdx and spdx not in seen_spdx:
            licenses.append({"raw": c, "spdx": spdx, "url": None, "source": "pypi:metadata", "expression": False})
            seen_spdx.add(spdx)

    if meta["license_field"] and meta["license_field"].lower() not in ("", "unknown", "unlicense"):
        spdx, matched = normalize_spdx(meta["license_field"])
        if not (spdx and spdx in seen_spdx):
            licenses.append({
                "raw": meta["license_field"], "spdx": spdx if matched else None,
                "url": None, "source": "pypi:metadata", "expression": False,
            })
            if spdx:
                seen_spdx.add(spdx)

    note = None if licenses else "PyPI metadata present but no License field / classifier"
    return {"licenses": licenses, "note": note, "none_source": "none:not-declared"}


# --------------------------------------------------------------------------
# Part 4: CycloneDX enrichment
# --------------------------------------------------------------------------

_LICENSE_PROP_PREFIX = "cra:license-"


def _cdx_license_entries(raw_licenses: list[dict]) -> tuple[list[dict], str]:
    """Turn resolved {name/raw, spdx, url} entries into CycloneDX license
    objects, never collapsing a found-but-unmatched raw string into nothing.
    Returns (cdx_licenses, status) where status is "resolved" (all matched),
    "unmatched" (none matched), or "partial" (mixed, dual-license case)."""
    cdx: list[dict] = []
    matched_any = False
    unmatched_any = False
    for lic in raw_licenses:
        raw = lic.get("raw") or lic.get("name")
        spdx = lic.get("spdx")
        url = lic.get("url")
        if lic.get("expression"):
            # PEP 639 license-expression: may be compound ("A OR B") -- goes
            # in CycloneDX's own `expression` field, not `license.id`.
            cdx.append({"expression": spdx})
            matched_any = True
            continue
        if spdx:
            entry = {"license": {"id": spdx}}
            if url:
                entry["license"]["url"] = url
            cdx.append(entry)
            matched_any = True
        else:
            entry = {"license": {"name": raw or "(unnamed license)"}}
            if url:
                entry["license"]["url"] = url
            cdx.append(entry)
            unmatched_any = True
    if matched_any and unmatched_any:
        status = "partial"
    elif matched_any:
        status = "resolved"
    elif unmatched_any:
        status = "unmatched"
    else:
        status = "none"
    return cdx, status


def _set_license_properties(comp: dict, source: str, status: str, note: str | None) -> None:
    props = comp.setdefault("properties", [])
    # idempotent: strip any cra:license-* this script wrote on a previous run
    props[:] = [p for p in props if not p.get("name", "").startswith(_LICENSE_PROP_PREFIX)]
    props.append({"name": "cra:license-source", "value": source})
    props.append({"name": "cra:license-status", "value": status})
    if note:
        props.append({"name": "cra:license-note", "value": note})


def _apply_resolution(comp: dict, raw_licenses: list[dict], source_if_found: str,
                       none_source: str, note_if_none: str) -> None:
    """none_source must be "none:not-declared" (a real source was read and
    genuinely has no license) or "unknown:not-determined" (no source could
    be found/read at all) -- never the old flat "none". See the module
    docstring for why these are kept apart."""
    if raw_licenses:
        cdx, status = _cdx_license_entries(raw_licenses)
        comp["licenses"] = cdx
        _set_license_properties(comp, source_if_found, status, None)
    else:
        # outcome 3: nothing found anywhere. Never leave a stale/empty
        # `licenses` key behind -- absent is the marker for this state.
        comp.pop("licenses", None)
        _set_license_properties(comp, none_source, "none", note_if_none)


def _parse_gav(comp: dict) -> tuple[str, str, str] | None:
    """group, artifact, version from a Gradle/Maven CycloneDX component.
    Prefers `name` ("group:artifact", set by ecosystems.py / gradle_tree.py)
    and falls back to parsing the purl."""
    name = comp.get("name") or ""
    if ":" in name:
        group, _, artifact = name.partition(":")
        if group and artifact:
            return group, artifact, comp.get("version", "")
    purl = comp.get("purl") or ""
    m = re.match(r"^pkg:maven/([^/]+)/([^@]+)@(.+)$", purl)
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None


def enrich_gradle_component(comp: dict, cache_root: Path, cache_available: bool,
                             network_enabled: bool = True,
                             maven_fetch_cache: Path | None = None) -> None:
    if not cache_available:
        comp.pop("licenses", None)
        _set_license_properties(comp, "unknown:not-determined", "none",
                                 f"gradle cache dir not found: {cache_root}")
        return

    gav = _parse_gav(comp)
    if gav is None:
        comp.pop("licenses", None)
        _set_license_properties(comp, "unknown:not-determined", "none",
                                 f"could not determine group:artifact:version from component "
                                 f"(name={comp.get('name')!r}, purl={comp.get('purl')!r})")
        return
    group, artifact, version = gav

    res = resolve_license(cache_root, group, artifact, version,
                           network_enabled=network_enabled, maven_fetch_cache=maven_fetch_cache)

    if res["outcome"] == "found":
        raw_licenses = [
            {"raw": lic["name"], "spdx": normalize_spdx(lic["name"] or "")[0], "url": lic["url"]}
            for lic in res["licenses"]
        ]
        _apply_resolution(comp, raw_licenses, res["source"], "unknown:not-determined", "")
        return

    # Neither the local cache nor (if enabled) the network had a usable POM
    # chain. Last resort: the component's own cached .jar/.aar, if Gradle
    # happens to have one locally (this is exactly the shape of the common
    # "aar/jar present, no adjacent .pom" case -- see the module docstring).
    archive_path = find_artifact_archive(cache_root, group, artifact, version)
    archive_res = resolve_from_archive(archive_path) if archive_path is not None else None

    if archive_res is not None and archive_res["outcome"] == "found":
        raw_licenses = [
            {"raw": lic["name"], "spdx": normalize_spdx(lic["name"] or "")[0], "url": lic["url"]}
            for lic in archive_res["licenses"]
        ]
        _apply_resolution(comp, raw_licenses, "archive:manifest", "unknown:not-determined", "")
        return

    # Still nothing. "declared-empty" means resolve_license actually read a
    # real POM through to the end of its chain and it had no <licenses> --
    # that is a fact about the component, not a data gap, so it gets
    # none:not-declared. Everything else (POM never even readable, archive
    # unusable/absent too) is a gap in our data: unknown:not-determined.
    none_source = "none:not-declared" if res["outcome"] == "declared-empty" else "unknown:not-determined"
    last = res["trail"][-1] if res["trail"] else {}
    note = f"unresolved: {last.get('status', 'unknown')}"
    if archive_res is not None:
        note += f"; archive checked: {archive_res['note']}"
    _apply_resolution(comp, [], none_source, none_source, note)


def enrich_pypi_component(comp: dict, offline: bool, req_overrides: dict[str, dict] | None = None) -> None:
    name = comp.get("name") or ""
    props = {p["name"]: p["value"] for p in comp.get("properties", []) or []}
    unpinned = props.get("cra:version-unpinned") == "true"
    version = None if unpinned else comp.get("version")
    pinned = not unpinned and bool(version)

    override = (req_overrides or {}).get(name.lower())
    if override:
        pinned = override["pinned"]
        version = override["version"] or version

    result = resolve_python_license(name, version, pinned, offline)
    raw_licenses = result["licenses"]
    note = result["note"] or ""
    none_source = result.get("none_source", "unknown:not-determined")
    _apply_resolution(comp, raw_licenses, "pypi:metadata", none_source, note)


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def enrich_bom(bom: dict, gradle_cache: Path, offline_python: bool,
               requirements_path: Path | None = None,
               offline: bool = False,
               maven_fetch_cache: Path | None = None) -> dict:
    """Mutates bom["components"] in place. Returns a summary dict.

    `offline` disables the Gradle-side network POM fetch (fix #1) -- network
    fetch is ON by default, matching scripts/collect_licenses.py in the
    earlier tooling this was ported from. `offline_python` is the
    existing, separate PyPI-side flag."""
    cache_available = gradle_cache.is_dir()
    if not cache_available:
        print(f"  ! gradle cache dir not found: {gradle_cache} -- "
              "all gradle components fall back to network fetch / archive scan"
              + (" (both disabled by --offline)" if offline else ""), file=sys.stderr)

    network_enabled = not offline
    if maven_fetch_cache is None:
        maven_fetch_cache = DEFAULT_MAVEN_FETCH_CACHE
    print(f"  Gradle POM network fetch: {'ON' if network_enabled else 'OFF (--offline)'}"
          + (f"  (cache: {maven_fetch_cache})" if network_enabled else ""), file=sys.stderr)

    req_overrides: dict[str, dict] = {}
    if requirements_path is not None:
        if not requirements_path.is_file():
            print(f"  ! --requirements file not found: {requirements_path} -- ignored",
                  file=sys.stderr)
        else:
            for r in parse_requirements(requirements_path):
                req_overrides[r["name"].lower()] = {
                    "pinned": r["pinned"],
                    "version": r["version"] if r["pinned"] else None,
                }

    counts = {
        "gradle": 0, "python": 0,
        "resolved": 0, "unmatched": 0, "partial": 0, "none": 0,
        # the two ways a component can land in "none" -- kept separate so a
        # report never reads "45 components, unknown license" when the truth
        # is "0 confirmed license-less, ~45 we simply couldn't determine".
        "none_not_declared": 0, "none_not_determined": 0,
    }

    for comp in bom.get("components", []) or []:
        props = {p["name"]: p["value"] for p in comp.get("properties", []) or []}
        ecosystem = props.get("cra:ecosystem")

        if ecosystem == "gradle":
            counts["gradle"] += 1
            enrich_gradle_component(comp, gradle_cache, cache_available,
                                     network_enabled=network_enabled,
                                     maven_fetch_cache=maven_fetch_cache)
        elif ecosystem == "pypi":
            counts["python"] += 1
            enrich_pypi_component(comp, offline_python, req_overrides)
        else:
            # composer / npm already carry a vendor-declared license from
            # their lockfile via sbom_gen.py -- not this script's job.
            continue

        comp_props = comp.get("properties", [])
        status = next(
            (p["value"] for p in comp_props if p["name"] == "cra:license-status"),
            "none",
        )
        counts[status] = counts.get(status, 0) + 1
        if status == "none":
            source = next(
                (p["value"] for p in comp_props if p["name"] == "cra:license-source"),
                "unknown:not-determined",
            )
            if source == "none:not-declared":
                counts["none_not_declared"] += 1
            else:
                counts["none_not_determined"] += 1

    return counts


def _default_output_path(sbom_path: Path) -> Path:
    name = sbom_path.name
    if name.endswith(".cdx.json"):
        base = name[: -len(".cdx.json")]
        return sbom_path.with_name(f"{base}.enriched.cdx.json")
    return sbom_path.with_name(f"{sbom_path.stem}.enriched{sbom_path.suffix}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Enrich a CycloneDX SBOM (sbom_gen.py output) with resolved "
                     "Gradle/Maven and Python component licenses"
    )
    ap.add_argument("--sbom", required=True, type=Path, help="path to sbom.cdx.json to enrich")
    ap.add_argument("--gradle-cache", type=Path, default=DEFAULT_GRADLE_CACHE,
                     help=f"path to Gradle modules-2/files-2.1 cache dir "
                          f"(default: {DEFAULT_GRADLE_CACHE})")
    ap.add_argument("--requirements", type=Path, default=None,
                     help="optional requirements.txt, used only to refine which PyPI "
                          "components are pinned (component version/pin info already in "
                          "the SBOM is used when this is omitted)")
    ap.add_argument("--offline-python", action="store_true",
                     help="skip PyPI network lookups for python components (they resolve to "
                          "cra:license-source=unknown:not-determined)")
    ap.add_argument("--offline", action="store_true",
                     help="disable the Gradle-side network POM fetch (fix for components whose "
                          "local Gradle cache holds an .aar/.jar but no adjacent .pom); network "
                          "fetch is ON by default. With --offline, those components fall back to "
                          "the local .jar/.aar archive scan and then to "
                          "cra:license-source=unknown:not-determined")
    ap.add_argument("--maven-fetch-cache", type=Path, default=None,
                     help="directory to cache POMs fetched over the network (default: "
                          "<sbom-dir>/maven-fetch-cache); reused on re-runs, never re-fetched "
                          "once cached")
    ap.add_argument("-o", "--out", type=Path, default=None,
                     help="output path (default: <sbom-name>.enriched.cdx.json, "
                          "never overwrites --sbom)")
    ap.add_argument("--in-place", action="store_true",
                     help="overwrite --sbom directly instead of writing a new file")
    args = ap.parse_args()

    if not args.sbom.is_file():
        print(f"no such file: {args.sbom}", file=sys.stderr)
        return 1
    if args.in_place and args.out:
        print("--in-place and -o/--out are mutually exclusive", file=sys.stderr)
        return 1

    out_path = args.sbom if args.in_place else (args.out or _default_output_path(args.sbom))

    try:
        bom = json.loads(args.sbom.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"could not read SBOM: {e}", file=sys.stderr)
        return 1

    maven_fetch_cache = args.maven_fetch_cache or (args.sbom.resolve().parent / "maven-fetch-cache")

    counts = enrich_bom(bom, args.gradle_cache, args.offline_python, args.requirements,
                         offline=args.offline, maven_fetch_cache=maven_fetch_cache)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")

    total = counts["gradle"] + counts["python"]
    resolved = counts["resolved"] + counts["partial"]
    print(f"  Components enriched:      {total}  (gradle {counts['gradle']}, python {counts['python']})")
    print(f"    resolved (>=1 SPDX id): {resolved}" + (f"  (of which partial dual-license: {counts['partial']})" if counts["partial"] else ""))
    print(f"    raw text, no SPDX match: {counts['unmatched']}")
    print(f"    confirmed no license declared:  {counts['none_not_declared']}")
    print(f"    could not be determined:        {counts['none_not_determined']}")
    print(f"\n  Wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
