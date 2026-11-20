"""
Regression tests for gradle_tree.py against the resolved-tree line forms its
own docstring documents:

    +--- group:name:1.2.3                       plain
    +--- group:name:1.2.3 -> 2.0.0              version substituted
    |    \\--- group:name:1.0 -> 2.0 (*)         subtree omitted (already shown)
    +--- group:name:1.0 -> 2.0 (c)              version constraint
    +--- group:name (n)                         not resolved

Per the task background, resolved-tree parsing already handles all of these
correctly — this file is regression protection, not a new fix. It also
covers a flavor-prefixed configuration name (prodReleaseRuntimeClasspath)
alongside a plain one (releaseRuntimeClasspath) in the same fixture, to
confirm configuration-name handling doesn't assume no flavor prefix.
"""

from __future__ import annotations

from conftest import FIXTURES_DIR

from cra_kit.gradle_tree import parse, to_components

DEPS = FIXTURES_DIR / "gradle_tree_markers" / "deps.txt"


def _by_name(comps):
    return {c["name"]: c for c in comps}


def _prop(comp: dict, name: str) -> str | None:
    for p in comp["properties"]:
        if p["name"] == name:
            return p["value"]
    return None


def test_release_config_plain_and_substituted_versions():
    parsed = parse(DEPS, "releaseRuntimeClasspath")
    assert parsed["configuration"] == "releaseRuntimeClasspath"
    comps = _by_name(to_components(parsed))

    # plain
    assert comps["com.example:core"]["version"] == "1.0.0"
    assert _prop(comps["com.example:core"], "cra:direct") == "true"

    # version substituted on resolution ( -> )
    assert comps["com.example:util"]["version"] == "2.0.0"


def test_release_config_omitted_subtree_still_a_component_with_resolved_version():
    parsed = parse(DEPS, "releaseRuntimeClasspath")
    comps = _by_name(to_components(parsed))
    # (*) marks a subtree already printed elsewhere — the node itself is
    # still a real transitive dependency and must appear, using the
    # substituted version, not the requested one.
    helper = comps["com.example:helper"]
    assert helper["version"] == "2.0.0"
    assert _prop(helper, "cra:direct") == "false"


def test_release_config_constraint_and_unresolved_excluded():
    parsed = parse(DEPS, "releaseRuntimeClasspath")
    comps = _by_name(to_components(parsed))
    # (c) — a version constraint is a resolution rule, not a shipped artefact
    assert "com.example:constrained" not in comps
    # (n) — not resolved at all
    assert "com.example:missing" not in comps


def test_flavor_prefixed_configuration_name_is_accepted():
    parsed = parse(DEPS, "prodReleaseRuntimeClasspath")
    assert parsed["configuration"] == "prodReleaseRuntimeClasspath"
    comps = _by_name(to_components(parsed))
    # this block only lists core + flavor-only — util/helper/constrained/missing
    # belong to the release block and must not bleed across
    assert set(comps) == {"com.example:core", "com.example:flavor-only"}
    assert comps["com.example:flavor-only"]["version"] == "5.0.0"


def test_no_configuration_given_picks_the_first_block():
    # mirrors gradlew's own default: when --gradle-configuration isn't
    # passed, the first configuration block in the file wins
    parsed = parse(DEPS, None)
    assert parsed["configuration"] == "releaseRuntimeClasspath"
