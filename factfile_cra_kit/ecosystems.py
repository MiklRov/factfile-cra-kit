#!/usr/bin/env python3
"""
Ecosystem parsers for the SBOM generator.

Each parser answers one question: which third-party components end up in the
product that is placed on the market. Not "what is in the project", but what
is shipped to the user — these are different sets, and an SBOM under Annex I
Part II needs the second one.

Supported: gradle (Kotlin/Android), pypi (Python), composer (PHP), npm (Node).

GRADLE MULTI-MODULE. A root `build.gradle.kts` in a multi-module project
typically only declares plugins (`apply false`) — the actual `dependencies {}`
blocks live in each module's own build file, and the modules themselves are
declared in `settings.gradle.kts` / `settings.gradle` via `include(...)`.
Static, root-only parsing of such a project sees no `dependencies` block and
silently yields zero components — indistinguishable from "this project has no
dependencies", which is how a wrong `sbom_gen.py <repo-root>` invocation used
to produce an empty, exit-0 SBOM. `parse_gradle()` below first looks for a
settings file at the given root; if one exists, it discovers every declared
module, parses each module's own build file (reusing the exact same per-file
logic used for single-module invocations), and merges the results — tagging
each component with `cra:module` so it is traceable to the module that
declared it. Inter-module dependencies (`implementation(project(":x"))`) are
not third-party components and are already excluded: `_DEP_LINE` only matches
a `libs.alias` or a quoted `"group:name[:version]"` coordinate, and
`project(...)` matches neither.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

# --------------------------------------------------------------------------
# Gradle / Android
# --------------------------------------------------------------------------

# Configurations whose contents actually end up in the shipped artefact.
SHIPPED_CONFIGS = {"implementation", "api", "runtimeOnly"}

# Build-time and test configurations: these do not reach the APK/AAB.
# ksp and kapt do compile-time code generation; the processor itself is not shipped.
BUILD_ONLY_CONFIGS = {
    "ksp", "kapt", "annotationProcessor", "compileOnly", "compileOnlyApi",
    "testImplementation", "androidTestImplementation", "testRuntimeOnly",
    "debugImplementation", "releaseCompileOnly", "lintChecks",
}

_DEP_LINE = re.compile(
    r"""^\s*(?P<config>[A-Za-z]+)\s*\(\s*
        (?:platform\s*\(\s*)?
        (?:
            libs\.(?P<alias>[A-Za-z0-9_.]+)
          | "(?P<coord>[^"]+)"
        )
    """,
    re.VERBOSE,
)


def _catalog(toml_path: Path) -> dict[str, dict]:
    """Parse libs.versions.toml into a mapping of alias -> library details."""
    if not toml_path.exists():
        return {}
    data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    versions = data.get("versions", {})
    out: dict[str, dict] = {}
    for alias, spec in (data.get("libraries") or {}).items():
        if isinstance(spec, str):
            # short form "group:name:version"
            parts = spec.split(":")
            if len(parts) == 3:
                out[alias] = {"group": parts[0], "name": parts[1], "version": parts[2]}
            continue
        group = spec.get("group")
        name = spec.get("name")
        if not group or not name:
            # module = "group:name" form
            mod = spec.get("module", "")
            if ":" in mod:
                group, _, name = mod.partition(":")
        if not group or not name:
            continue
        version = spec.get("version")
        if isinstance(version, dict):
            version = version.get("ref") and versions.get(version["ref"])
        elif ref := spec.get("version.ref"):
            version = versions.get(ref)
        out[alias] = {"group": group, "name": name, "version": version}
    return out


def _alias_key(dotted: str) -> str:
    """libs.androidx.core.ktx -> androidx-core-ktx"""
    return dotted.replace(".", "-")


_INCLUDE_CALL = re.compile(
    r"\binclude\s*\(?\s*((?:[\"'][^\"']+[\"']\s*,?\s*)+)\)?"
)
_QUOTED = re.compile(r"[\"']([^\"']+)[\"']")
_PROJECT_DIR_OVERRIDE = re.compile(
    r"project\(\s*[\"']:(?P<path>[^\"']+)[\"']\s*\)\s*\.projectDir\s*=\s*file\(\s*"
    r"[\"'](?P<dir>[^\"']+)[\"']\s*\)"
)


def discover_gradle_modules(root: Path) -> list[tuple[str, Path]]:
    """
    Parse settings.gradle.kts / settings.gradle for `include(...)` and map
    each included module path to its directory.

    Handles the Kotlin- and Groovy-DSL forms of `include`, single or multiple
    args per call (`include(":a")`, `include(":a", ":b")`, `include ":a"`).
    `:a:b` maps to `a/b` per Gradle's colon-to-path convention, unless a
    `project(":a:b").projectDir = file("...")` override says otherwise.

    Returns [] when there is no settings file — the caller falls back to
    single-module parsing of `root` itself.
    """
    settings = root / "settings.gradle.kts"
    if not settings.exists():
        settings = root / "settings.gradle"
    if not settings.exists():
        return []

    text = settings.read_text(encoding="utf-8")

    include_paths: list[str] = []
    for call in _INCLUDE_CALL.finditer(text):
        for token in _QUOTED.findall(call.group(1)):
            if token.startswith(":"):
                include_paths.append(token)

    overrides = {
        m.group("path"): m.group("dir")
        for m in _PROJECT_DIR_OVERRIDE.finditer(text)
    }

    modules: list[tuple[str, Path]] = []
    for path in include_paths:
        bare = path.lstrip(":")
        if bare in overrides:
            module_dir = (root / overrides[bare]).resolve()
        else:
            module_dir = root.joinpath(*bare.split(":"))
        modules.append((bare, module_dir))
    return modules


def parse_gradle(root: Path, catalog_path: Path | None = None) -> list[dict]:
    """
    Entry point: single-module or multi-module, decided by whether `root`
    has a settings.gradle(.kts) declaring submodules.
    """
    modules = discover_gradle_modules(root)
    if not modules:
        return _parse_module(root, catalog_path, module_name=root.name)

    by_purl: dict[str, dict] = {}
    for name, module_dir in modules:
        if not module_dir.is_dir():
            continue
        for comp in _parse_module(module_dir, catalog_path, module_name=name):
            purl = comp["purl"]
            if purl not in by_purl:
                by_purl[purl] = comp
                continue
            # Same group:name@version declared by more than one module (the
            # common case — modules share one version catalog): keep a single
            # component, and record every contributing module rather than
            # only the first one seen. When modules disagree on the VERSION
            # of the same group:name, that is real information about what
            # actually ships in each module's own artefact — those stay as
            # separate components (different purls), each still carrying its
            # own single-module cra:module tag, so the divergence is visible
            # in the output itself rather than collapsed away.
            existing = by_purl[purl]
            mod_prop = next(
                p for p in existing["properties"] if p["name"] == "cra:module"
            )
            mods = set(mod_prop["value"].split(", ")) | {name}
            mod_prop["value"] = ", ".join(sorted(mods))
    return list(by_purl.values())


def _parse_module(
    module_dir: Path, catalog_path: Path | None = None, module_name: str | None = None
) -> list[dict]:
    """
    Parse a single module's build.gradle.kts together with the version catalog.

    IMPORTANT ON COVERAGE. Gradle resolves transitive dependencies at build time;
    static parsing cannot see them. The result is the top-level dependencies,
    i.e. exactly the minimum required by Annex I Part II point 1.
    For the full tree, use the output of `./gradlew :app:dependencies`.
    """
    if module_name is None:
        module_name = module_dir.name
    build = module_dir / "build.gradle.kts"
    if not build.exists():
        build = module_dir / "build.gradle"
    if not build.exists():
        return []

    if catalog_path is None:
        for up in (module_dir.parent, module_dir.parent.parent):
            cand = up / "gradle" / "libs.versions.toml"
            if cand.exists():
                catalog_path = cand
                break
    cat = _catalog(catalog_path) if catalog_path else {}

    text = build.read_text(encoding="utf-8")
    block = re.search(r"^dependencies\s*\{(.*?)^\}", text, re.S | re.M)
    if not block:
        return []

    boms: list[str] = []
    comps: list[dict] = []
    seen: set[str] = set()

    for line in block.group(1).splitlines():
        if line.lstrip().startswith("//"):
            continue
        m = _DEP_LINE.match(line)
        if not m:
            continue
        config = m.group("config")
        is_platform = "platform(" in line

        if alias := m.group("alias"):
            info = cat.get(_alias_key(alias))
            if not info:
                continue
            group, name, version = info["group"], info["name"], info["version"]
        else:
            coord = m.group("coord")
            parts = coord.split(":")
            if len(parts) < 2:
                continue
            group, name = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else None

        if is_platform and version:
            boms.append(f"{group}:{name}:{version}")

        shipped = config in SHIPPED_CONFIGS
        version_managed = version is None
        purl_ver = version or "unspecified"
        purl = f"pkg:maven/{group}/{name}@{purl_ver}"
        if purl in seen:
            continue
        seen.add(purl)

        comp: dict = {
            "bom-ref": purl,
            "type": "library",
            "name": f"{group}:{name}",
            "version": purl_ver,
            "purl": purl,
            "scope": "required" if shipped else "excluded",
            "properties": [
                {"name": "cra:ecosystem", "value": "gradle"},
                {"name": "cra:direct", "value": "true"},
                {"name": "cra:dev", "value": "false" if shipped else "true"},
                {"name": "cra:gradle-configuration", "value": config},
                {"name": "cra:module", "value": module_name},
            ],
        }
        if version_managed:
            comp["properties"].append(
                {"name": "cra:version-managed-by-bom", "value": "true"}
            )
        comps.append(comp)

    # record which BOM manages the versions that were not stated explicitly
    if boms:
        for c in comps:
            if any(p["name"] == "cra:version-managed-by-bom" for p in c["properties"]):
                c["properties"].append(
                    {"name": "cra:bom", "value": ", ".join(boms)}
                )
    return comps


# --------------------------------------------------------------------------
# PyPI
# --------------------------------------------------------------------------

_REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
    r"(?P<op>==|>=|<=|~=|>|<)?\s*(?P<version>[A-Za-z0-9._*+!-]+)?"
)


def parse_pypi(req_path: Path, dev: bool = False) -> list[dict]:
    """Parse requirements.txt. Only pinned versions (==) are taken into account.

    This is DECLARED-only coverage: requirements.txt states what the project's
    author chose to write down, not what actually got installed. It sees none
    of the transitive closure a real `pip install` pulls in — see
    `parse_pip_freeze()` below for the resolved-environment counterpart, which
    is the PyPI analogue of `--gradle-tree` vs static Gradle parsing. Every
    component from this function is tagged `cra:pypi-source=declared` so a
    reader of the final SBOM can tell it apart from a resolved scan.
    """
    if not req_path.exists():
        return []
    comps: list[dict] = []
    seen: set[str] = set()
    for raw in req_path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        version = m.group("version") if m.group("op") == "==" else None
        purl_ver = version or "unspecified"
        purl = f"pkg:pypi/{name.lower()}@{purl_ver}"
        if purl in seen:
            continue
        seen.add(purl)
        props = [
            {"name": "cra:ecosystem", "value": "pypi"},
            {"name": "cra:direct", "value": "true"},
            {"name": "cra:dev", "value": "true" if dev else "false"},
            {"name": "cra:pypi-source", "value": "declared"},
        ]
        if version is None:
            props.append({"name": "cra:version-unpinned", "value": "true"})
        comps.append({
            "bom-ref": purl,
            "type": "library",
            "name": name,
            "version": purl_ver,
            "purl": purl,
            "scope": "optional" if dev else "required",
            "properties": props,
        })
    return comps


# --------------------------------------------------------------------------
# PyPI — resolved environment (`pip freeze`)
# --------------------------------------------------------------------------

_FREEZE_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(?P<version>[A-Za-z0-9._+!-]+)\s*$"
)


def _normalize_pypi_name(name: str) -> str:
    """PEP 503 normalisation: case-fold and treat '.', '_', '-' as equivalent.
    Used only to cross-reference names between requirements.txt and a
    pip-freeze file — the purl/display name itself is left as-is elsewhere.
    """
    return re.sub(r"[-_.]+", "-", name.lower())


def _direct_names_from_requirements(req_paths: list[Path]) -> set[str]:
    """Normalised names of every package declared in any of the given
    requirements.txt files (that actually exist). Used to tag cra:direct on
    pip-freeze components — requirements.txt is the only source of "this is
    top-level, not a transitive pull-in" information a flat freeze file does
    not carry on its own.
    """
    direct: set[str] = set()
    for req_path in req_paths:
        if not req_path.exists():
            continue
        for raw in req_path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = _REQ_LINE.match(line)
            if not m:
                continue
            direct.add(_normalize_pypi_name(m.group("name")))
    return direct


def parse_pip_freeze(
    freeze_path: Path,
    requirements_paths: list[Path] | None = None,
    dev: bool = False,
) -> list[dict]:
    """Parse the output of `pip freeze` (one `name==version` per line) into
    the full, actually-resolved PyPI component set — the counterpart to
    `gradle_tree.py` for the Python ecosystem, and for the same reason:
    `requirements.txt` is hand-maintained and only ever shows the top-level
    packages someone chose to pin; `pip freeze`, run inside the real target
    environment, shows everything actually installed, transitive included.

    `pip freeze` output is a flat list — unlike a Gradle resolved-tree dump,
    it carries no parent/child structure, so "direct vs transitive" cannot be
    read off the file itself. If `requirements_paths` is given, any package
    named there is tagged `cra:direct=true`; everything else found only in
    the freeze file is `cra:direct=false` (real transitive information,
    cross-referenced against the declared file). If NO requirements file is
    available at all, `cra:direct` is tagged `"unknown"` rather than
    defaulting silently to true or false — the freeze file alone genuinely
    does not contain this information, and guessing would misrepresent it.

    Tolerant of a UTF-8 BOM and CRLF line endings — both observed in a real
    `pip freeze` capture taken from a Docker container via `docker exec ...
    pip freeze` piped through a Windows shell.
    """
    if not freeze_path.exists():
        return []

    direct_names: set[str] | None = None
    if requirements_paths:
        existing = [p for p in requirements_paths if p.exists()]
        if existing:
            direct_names = _direct_names_from_requirements(existing)

    text = freeze_path.read_text(encoding="utf-8-sig")
    comps: list[dict] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _FREEZE_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        version = m.group("version")
        purl = f"pkg:pypi/{name.lower()}@{version}"
        if purl in seen:
            continue
        seen.add(purl)

        if direct_names is None:
            direct_value = "unknown"
        else:
            direct_value = (
                "true" if _normalize_pypi_name(name) in direct_names else "false"
            )

        props = [
            {"name": "cra:ecosystem", "value": "pypi"},
            {"name": "cra:direct", "value": direct_value},
            {"name": "cra:dev", "value": "true" if dev else "false"},
            {"name": "cra:pypi-source", "value": "resolved"},
        ]
        comps.append({
            "bom-ref": purl,
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "scope": "optional" if dev else "required",
            "properties": props,
        })
    return comps


# --------------------------------------------------------------------------
# auto-detection
# --------------------------------------------------------------------------

def detect(root: Path) -> list[str]:
    """Which ecosystems are present in a directory."""
    found = []
    if (root / "build.gradle.kts").exists() or (root / "build.gradle").exists():
        found.append("gradle")
    if (root / "requirements.txt").exists():
        found.append("pypi")
    if (root / "composer.lock").exists():
        found.append("composer")
    if (root / "package-lock.json").exists():
        found.append("npm")
    return found
