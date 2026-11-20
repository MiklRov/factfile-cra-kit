#!/usr/bin/env python3
"""Run cra-kit's sbom_gen from a clone: `python3 sbom_gen.py ...`.

Installed, the same tool is the `cra-kit-sbom` command.
The code lives in factfile_cra_kit/sbom_gen.py.
"""

from factfile_cra_kit.sbom_gen import main

if __name__ == "__main__":
    raise SystemExit(main())
