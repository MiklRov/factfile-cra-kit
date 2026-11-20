#!/usr/bin/env python3
"""Run cra-kit's vuln_scan from a clone: `python3 vuln_scan.py ...`.

Installed, the same tool is the `cra-kit-vuln-scan` command.
The code lives in cra_kit/vuln_scan.py.
"""

from cra_kit.vuln_scan import main

if __name__ == "__main__":
    raise SystemExit(main())
