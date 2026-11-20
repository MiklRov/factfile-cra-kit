#!/usr/bin/env python3
"""Run cra-kit's validate from a clone: `python3 validate.py ...`.

Installed, the same tool is the `cra-kit-validate` command.
The code lives in cra_kit/validate.py.
"""

from cra_kit.validate import main

if __name__ == "__main__":
    raise SystemExit(main())
