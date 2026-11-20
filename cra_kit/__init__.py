"""
cra-kit: Annex VII technical documentation for Regulation (EU) 2024/2847,
assembled and cross-checked.

Installed, each tool is a command:

    cra-kit-build           the technical file and the declaration
    cra-kit-sbom            the CycloneDX SBOM
    cra-kit-vuln-scan       OSV lookup for the SBOM's components
    cra-kit-validate        the essential-requirements matrix
    cra-kit-license-enrich  licences for Gradle/Maven and PyPI components

From a clone, the same tools run as `python3 build.py`, `python3 sbom_gen.py`
and so on: the scripts in the repository root are thin wrappers around this
package.
"""

__version__ = "0.1.0"
