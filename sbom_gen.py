#!/usr/bin/env python3
"""
Generate a CycloneDX 1.6 SBOM from a project's dependency manifests.

Satisfies Annex I Part II point 1 of Regulation (EU) 2024/2847: an SBOM
"in a commonly used machine-readable format covering at the very least the
top-level dependencies of the product".

Deliberately implemented without external dependencies: it reads lock files
directly, because they are the source of truth about what actually shipped.

Supports: composer (PHP), npm (Node).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SPEC_VERSION = "1.6"
TOOL_NAME = "cra-kit-sbom"
TOOL_VERSION = "0.1.0"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _norm_licenses(raw) -> list[dict]:
    """composer gives a list, npm a string. Normalise to CycloneDX."""
    if not raw:
        return []
    values = raw if isinstance(raw, list) else [raw]
    out = []
    for v in values:
        if not isinstance(v, str) or not v.strip():
            continue
        # SPDX expressions (OR/AND/WITH) go in expression, plain ids in license.id
        if any(op in v for op in (" OR ", " AND ", " WITH ")):
            out.append({"expression": v})
        else:
            out.append({"license": {"id": v}})
    return out


def _ref(purl: str) -> str:
    """Stable bom-ref."""
    return purl


# --------------------------------------------------------------------------
# composer
# --------------------------------------------------------------------------

def parse_composer(root: Path, include_dev: bool = False) -> list[dict]:
    lock_path = root / "composer.lock"
    json_path = root / "composer.json"
    if not lock_path.exists():
        return []

    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    direct: set[str] = set()
    if json_path.exists():
        manifest = json.loads(json_path.read_text(encoding="utf-8"))
        direct |= set(manifest.get("require", {}).keys())
        if include_dev:
            direct |= set(manifest.get("require-dev", {}).keys())

    sections = ["packages"] + (["packages-dev"] if include_dev else [])

    components = []
    for section in sections:
        is_dev = section == "packages-dev"
        for pkg in lock.get(section, []) or []:
            name = pkg.get("name")
            version = (pkg.get("version") or "").lstrip("v")
            if not name or not version:
                continue
            purl = f"pkg:composer/{name}@{version}"
            comp: dict = {
                "bom-ref": _ref(purl),
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "scope": "optional" if is_dev else "required",
            }
            lic = _norm_licenses(pkg.get("license"))
            if lic:
                comp["licenses"] = lic
            if desc := pkg.get("description"):
                comp["description"] = desc[:500]

            src = pkg.get("source") or {}
            dist = pkg.get("dist") or {}
            refs = []
            if url := src.get("url"):
                refs.append({"type": "vcs", "url": url})
            if url := dist.get("url"):
                refs.append({"type": "distribution", "url": url})
            if url := pkg.get("homepage"):
                refs.append({"type": "website", "url": url})
            if refs:
                comp["externalReferences"] = refs

            if sha := dist.get("shasum"):
                comp["hashes"] = [{"alg": "SHA-1", "content": sha}]

            comp["properties"] = [
                {"name": "cra:ecosystem", "value": "composer"},
                {"name": "cra:direct", "value": "true" if name in direct else "false"},
                {"name": "cra:dev", "value": "true" if is_dev else "false"},
            ]
            components.append(comp)
    return components


# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------

def parse_npm(root: Path, include_dev: bool = False) -> list[dict]:
    lock_path = root / "package-lock.json"
    json_path = root / "package.json"
    if not lock_path.exists():
        return []

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("lockfileVersion", 0) < 2:
        print(
            f"  ! package-lock.json is version {lock.get('lockfileVersion')}; "
            "v2+ (npm 7+) is required. Skipping.",
            file=sys.stderr,
        )
        return []

    direct: set[str] = set()
    if json_path.exists():
        manifest = json.loads(json_path.read_text(encoding="utf-8"))
        direct |= set(manifest.get("dependencies", {}).keys())
        if include_dev:
            direct |= set(manifest.get("devDependencies", {}).keys())

    components = []
    for path, meta in (lock.get("packages") or {}).items():
        if not path:  # the root entry is the project itself, not a dependency
            continue
        if not isinstance(meta, dict):
            continue
        is_dev = bool(meta.get("dev") or meta.get("devOptional"))
        if is_dev and not include_dev:
            continue

        name = meta.get("name") or path.split("node_modules/")[-1]
        version = meta.get("version")
        if not name or not version:
            continue

        purl = f"pkg:npm/{name}@{version}"
        comp: dict = {
            "bom-ref": _ref(purl),
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "scope": "optional" if is_dev else "required",
        }
        lic = _norm_licenses(meta.get("license"))
        if lic:
            comp["licenses"] = lic
        if url := meta.get("resolved"):
            comp["externalReferences"] = [{"type": "distribution", "url": url}]
        if integrity := meta.get("integrity"):
            # format is "sha512-<base64>"
            if "-" in integrity:
                alg, _, val = integrity.partition("-")
                alg_map = {"sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1"}
                if alg in alg_map:
                    comp["properties_hash_raw"] = val  # kept verbatim, dropped below
                    comp["hashes"] = [{"alg": alg_map[alg], "content": val}]
            comp.pop("properties_hash_raw", None)

        comp["properties"] = [
            {"name": "cra:ecosystem", "value": "npm"},
            {"name": "cra:direct", "value": "true" if name in direct else "false"},
            {"name": "cra:dev", "value": "true" if is_dev else "false"},
        ]
        components.append(comp)
    return components


# --------------------------------------------------------------------------
# document assembly
# --------------------------------------------------------------------------

def _pypi_components(
    root: Path,
    extra_pypi: list[Path] | None,
    pip_freeze: Path | None,
    search_log: list[str],
) -> list[dict]:
    """Build the PyPI component set for one run.

    When `--pip-freeze` is given it is authoritative for the actual component
    list — it reflects an environment that was really resolved and installed,
    the same way `--gradle-tree` is authoritative over static Gradle parsing.
    `requirements.txt` (root + any `--pypi` extras) is then used only to
    inform `cra:direct` tagging on the freeze-derived components, never
    parsed a second time into components of its own — otherwise every package
    named in both files would be double-counted.

    Without `--pip-freeze`, falls back to declared-only parsing of
    requirements.txt, exactly as before.
    """
    from ecosystems import parse_pip_freeze, parse_pypi

    req_paths = [root / "requirements.txt"] + list(extra_pypi or [])

    if pip_freeze is not None:
        search_log.append(f"pypi (resolved via pip freeze): {pip_freeze}")
        for p in req_paths:
            search_log.append(f"pypi (declared, for cra:direct only): {p}")
        return parse_pip_freeze(pip_freeze, requirements_paths=req_paths)

    components: list[dict] = []
    for p in req_paths:
        search_log.append(f"pypi: {p}")
        components += parse_pypi(p)
    return components


def build_bom(
    root: Path,
    product_name: str,
    product_version: str,
    supplier: str | None,
    include_dev: bool,
    extra_pypi: list[Path] | None = None,
    gradle_tree: Path | None = None,
    gradle_configuration: str | None = None,
    pip_freeze: Path | None = None,
    search_log: list[str] | None = None,
) -> dict:
    """
    `search_log`, when passed, is appended in place with one human-readable
    line per manifest/lockfile/tree this run actually looked for — regardless
    of whether anything was found there. `main()` uses it to make the
    E-SBOM-01 "no components found" error name exactly what was checked,
    instead of a generic message.
    """
    if search_log is None:
        search_log = []

    components: list[dict] = []
    components += parse_composer(root, include_dev)
    search_log.append(f"composer: {root / 'composer.lock'}")
    components += parse_npm(root, include_dev)
    search_log.append(f"npm: {root / 'package-lock.json'}")

    # Gradle / Android
    try:
        from ecosystems import parse_gradle
        ecosystems_importable = True
    except ImportError:
        parse_gradle = None  # type: ignore
        ecosystems_importable = False

    if gradle_tree is not None:
        # A tree resolved by Gradle itself is always more accurate than static
        # parsing: it accounts for transitive dependencies, version substitution
        # during conflict resolution, and versions managed by platform BOMs.
        from gradle_tree import parse as parse_tree, to_components
        parsed = parse_tree(gradle_tree, gradle_configuration)
        components += to_components(parsed)
        search_log.append(
            f"gradle (resolved tree, configuration {parsed['configuration']!r}): "
            f"{gradle_tree}"
        )
        print(
            f"  Gradle: tree from configuration {parsed['configuration']}, "
            f"{len(parsed['nodes'])} nodes"
        )
        if ecosystems_importable:
            components += _pypi_components(root, extra_pypi, pip_freeze, search_log)
    elif parse_gradle is not None:
        settings = root / "settings.gradle.kts"
        if not settings.exists():
            settings = root / "settings.gradle"
        if settings.exists():
            search_log.append(
                f"gradle (multi-module via {settings.name}): modules declared "
                f"under {root}"
            )
        else:
            search_log.append(
                f"gradle: {root / 'build.gradle.kts'} or {root / 'build.gradle'}"
            )
        gradle_comps = parse_gradle(root)
        if not include_dev:
            gradle_comps = [
                c for c in gradle_comps
                if not any(
                    p["name"] == "cra:dev" and p["value"] == "true"
                    for p in c.get("properties", [])
                )
            ]
        components += gradle_comps

        components += _pypi_components(root, extra_pypi, pip_freeze, search_log)
    else:
        search_log.append("gradle/pypi: ecosystems.py not importable, skipped")

    # dedupe by purl, stable ordering
    seen: dict[str, dict] = {}
    for c in components:
        seen.setdefault(c["purl"], c)
    components = sorted(seen.values(), key=lambda c: (c["purl"]))

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    serial = hashlib.sha256(
        f"{product_name}|{product_version}|{len(components)}".encode()
    ).hexdigest()[:32]

    metadata: dict = {
        "timestamp": now,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                }
            ]
        },
        "component": {
            "bom-ref": f"pkg:generic/{product_name}@{product_version}",
            "type": "application",
            "name": product_name,
            "version": product_version,
        },
    }
    if supplier:
        metadata["supplier"] = {"name": supplier}
        metadata["component"]["supplier"] = {"name": supplier}

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-4{serial[13:16]}"
        f"-a{serial[17:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


def summarise(bom: dict) -> None:
    comps = bom["components"]
    by_eco: dict[str, int] = {}
    direct = 0
    no_license = 0
    for c in comps:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        eco = props.get("cra:ecosystem", "?")
        by_eco[eco] = by_eco.get(eco, 0) + 1
        if props.get("cra:direct") == "true":
            direct += 1
        if not c.get("licenses"):
            no_license += 1

    print(f"\n  Total components:         {len(comps)}")
    for eco, n in sorted(by_eco.items()):
        print(f"    {eco:<10} {n}")
    print(f"  Direct dependencies:      {direct}")
    print(f"  Without a stated licence: {no_license}", end="")
    print("  <- needs manual review" if no_license else "")


def _warn_if_static_only(bom: dict, gradle_tree: Path | None) -> None:
    """W-SBOM-02: warn (not fail) when the SBOM looks like it came only from
    static parsing of Gradle build files rather than a Gradle-resolved tree.

    Signal: every component is direct (cra:direct=true for all of them, i.e.
    zero transitive components) AND gradle is one of the ecosystems present
    AND the caller did not already pass --gradle-tree (in which case this
    warning would be pointless — a resolved tree was used).
    """
    if gradle_tree is not None:
        return
    comps = bom["components"]
    if not comps:
        return
    ecosystems = {
        p["value"]
        for c in comps
        for p in c.get("properties", [])
        if p["name"] == "cra:ecosystem"
    }
    if "gradle" not in ecosystems:
        return
    all_direct = all(
        any(
            p["name"] == "cra:direct" and p["value"] == "true"
            for p in c.get("properties", [])
        )
        for c in comps
    )
    if not all_direct:
        return
    print(
        "  ! W-SBOM-02: every component came from static parsing of Gradle "
        "build files — zero transitive dependencies were resolved. This "
        "looks like static manifest parsing, not a Gradle-resolved "
        "dependency tree. For the full picture, on the build machine run:\n"
        "      gradlew :<module>:dependencies --configuration <config> > deps.txt\n"
        "    then re-run this tool with --gradle-tree deps.txt "
        "--gradle-configuration <config>.",
        file=sys.stderr,
    )


def _pypi_declared_only_purls(bom: dict) -> list[str]:
    """purls of every PyPI component whose only source was declared parsing
    of requirements.txt (cra:pypi-source=declared) — i.e. no --pip-freeze
    was used to confirm it against a real resolved environment."""
    return [
        c["purl"]
        for c in bom["components"]
        for p in c.get("properties", [])
        if p["name"] == "cra:pypi-source" and p["value"] == "declared"
    ]


def _check_pypi_resolved_coverage(
    bom: dict, pip_freeze: Path | None, declared_only: bool
) -> str | None:
    """E-SBOM-02 (hard error) / W-SBOM-03 (warning, opt-in via --declared-only).

    Same severity class as E-SBOM-01, not a lesser one: tonight's real
    incident showed 27 packages declared in requirements.txt against 111
    actually resolved and running in the production container — including
    security-critical packages (cryptography, PyJWT, redis, sentry-sdk) that
    a declared-only scan cannot see at all. A PyPI component set built from
    requirements.txt alone is not "slightly incomplete", it is the same
    failure mode E-SBOM-01 already refuses to ship silently: an SBOM that
    looks complete (valid CycloneDX, non-empty, no warning) while omitting
    exactly the kind of component Annex I Part II's SBOM requirement exists
    to surface.

    If `pip_freeze` was given, every PyPI component is resolved-environment
    confirmed and this check is a no-op. Otherwise, if any PyPI component
    came only from declared parsing, this is a hard failure unless the
    caller explicitly passed `declared_only=True` (mirrors --allow-empty:
    an explicit, visible admission, not a silent default), in which case it
    is downgraded to a W-SBOM-03 warning instead.

    Returns the error message to print (and the caller should then refuse to
    write the file / return non-zero) when this is a hard failure, or None
    when it is not (either fully resolved, no PyPI components at all, or
    downgraded to the warning path — which this function also prints).
    """
    if pip_freeze is not None:
        return None
    declared_purls = _pypi_declared_only_purls(bom)
    if not declared_purls:
        return None

    fix = (
        "      pip freeze > freeze.txt   # run inside the real target "
        "environment/container\n"
        "    then re-run this tool with --pip-freeze freeze.txt."
    )

    if declared_only:
        print(
            "  ! W-SBOM-03: PyPI components came only from declared parsing "
            f"of requirements.txt ({len(declared_purls)} package(s)) — no "
            "--pip-freeze was given, so this reflects only declared "
            "top-level packages and likely undercounts the real, running "
            "dependency closure significantly. --declared-only was passed, "
            "so this is a warning, not a failure. For the full picture, on "
            "the target environment run:\n" + fix,
            file=sys.stderr,
        )
        return None

    return (
        "error: E-SBOM-02: PyPI components came only from declared parsing "
        f"of requirements.txt ({len(declared_purls)} package(s)) — no "
        "--pip-freeze was given. A requirements.txt-only scan reflects only "
        "declared top-level packages, not what actually runs: a real "
        "incident found 27 declared packages against 111 actually resolved "
        "and installed in the production container, including "
        "security-critical packages (cryptography, PyJWT, redis, "
        "sentry-sdk) completely invisible to the declared-only file. "
        "Shipping a technical-file SBOM built only from requirements.txt "
        "would silently misrepresent the product's real dependency closure "
        "— the same failure class E-SBOM-01 already refuses for an empty "
        "SBOM. To fix, on the target environment/container run:\n" + fix +
        "\n    If a declared-only scan is genuinely what you intend here, "
        "re-run with --declared-only to downgrade this to a warning."
    )


def generate(
    root: Path,
    product_name: str,
    product_version: str,
    supplier: str | None,
    include_dev: bool,
    out: Path,
    extra_pypi: list[Path] | None = None,
    gradle_tree: Path | None = None,
    gradle_configuration: str | None = None,
    pip_freeze: Path | None = None,
    allow_empty: bool = False,
    declared_only: bool = False,
) -> int:
    """Build the BOM, apply the E-SBOM-01 / E-SBOM-02 / W-SBOM-02 / W-SBOM-03
    checks, and write the file. Split out from main() so tests can call it
    directly without going through argparse/sys.argv."""
    search_log: list[str] = []
    bom = build_bom(
        root, product_name, product_version, supplier, include_dev,
        extra_pypi=extra_pypi,
        gradle_tree=gradle_tree,
        gradle_configuration=gradle_configuration,
        pip_freeze=pip_freeze,
        search_log=search_log,
    )

    if not bom["components"] and not allow_empty:
        print(
            "error: E-SBOM-01: no components found — refusing to write an "
            "empty SBOM",
            file=sys.stderr,
        )
        print(f"  Searched under {root}:", file=sys.stderr)
        for line in search_log:
            print(f"    - {line}", file=sys.stderr)
        print(
            "  If an empty SBOM is genuinely expected here (e.g. a module "
            "with no dependencies at all), re-run with --allow-empty.",
            file=sys.stderr,
        )
        return 1

    pypi_error = _check_pypi_resolved_coverage(bom, pip_freeze, declared_only)
    if pypi_error is not None:
        print(pypi_error, file=sys.stderr)
        return 1

    _warn_if_static_only(bom, gradle_tree)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"  SBOM written: {out}")
    summarise(bom)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="CycloneDX 1.6 SBOM generator for CRA Annex I Part II purposes"
    )
    ap.add_argument("root", type=Path, help="root of the product repository")
    ap.add_argument("--name", required=True, help="product name")
    ap.add_argument("--version", required=True, help="product version")
    ap.add_argument("--supplier", default=None, help="manufacturer / supplier")
    ap.add_argument(
        "--include-dev",
        action="store_true",
        help="include dev dependencies (off by default: they are not shipped "
        "with the product and do not belong in the product SBOM)",
    )
    ap.add_argument(
        "--pypi",
        type=Path,
        action="append",
        default=[],
        help="an additional requirements.txt (repeatable) — for example the "
        "backend that serves the application",
    )
    ap.add_argument(
        "--gradle-tree",
        type=Path,
        default=None,
        help="output of `gradlew :app:dependencies` — yields the full resolved "
        "tree instead of only the top level",
    )
    ap.add_argument(
        "--gradle-configuration",
        default=None,
        help="configuration name within the tree, e.g. prodReleaseRuntimeClasspath",
    )
    ap.add_argument(
        "--pip-freeze",
        type=Path,
        default=None,
        help="output of `pip freeze` run inside the real target "
        "environment/container — yields the full resolved PyPI component "
        "set instead of only what requirements.txt declares. Required "
        "unless --declared-only is passed (see E-SBOM-02).",
    )
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="write the SBOM even if zero components were found. E-SBOM-01 is "
        "a hard error by default — a silently empty SBOM has shipped as a "
        "false 'complete' file before. Only pass this when an empty SBOM is "
        "genuinely expected (e.g. a module with truly no dependencies).",
    )
    ap.add_argument(
        "--declared-only",
        action="store_true",
        help="allow a PyPI component set built only from requirements.txt, "
        "with no --pip-freeze. E-SBOM-02 is a hard error by default — a "
        "requirements.txt-only scan reflects declared top-level packages "
        "only and has been shown to omit ~75%% of what actually runs, "
        "including security-critical packages. Only pass this when a "
        "declared-only scan is genuinely what you intend (downgrades the "
        "check to warning W-SBOM-03 instead of failing).",
    )
    ap.add_argument("-o", "--out", type=Path, default=Path("sbom.cdx.json"))
    args = ap.parse_args()

    if not args.root.is_dir():
        print(f"no such directory: {args.root}", file=sys.stderr)
        return 1

    return generate(
        args.root, args.name, args.version, args.supplier, args.include_dev,
        out=args.out,
        extra_pypi=args.pypi,
        gradle_tree=args.gradle_tree,
        gradle_configuration=args.gradle_configuration,
        pip_freeze=args.pip_freeze,
        allow_empty=args.allow_empty,
        declared_only=args.declared_only,
    )


if __name__ == "__main__":
    raise SystemExit(main())
