#!/usr/bin/env python3
"""Run cra-kit's license_enrich from a clone: `python3 license_enrich.py ...`.

Installed, the same tool is the `cra-kit-license-enrich` command.
The code lives in cra_kit/license_enrich.py.
"""

from cra_kit.license_enrich import main

if __name__ == "__main__":
    raise SystemExit(main())
