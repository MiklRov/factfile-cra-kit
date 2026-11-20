#!/usr/bin/env python3
"""Run cra-kit's build from a clone: `python3 build.py ...`.

Installed, the same tool is the `cra-kit-build` command.
The code lives in cra_kit/build.py.
"""

from cra_kit.build import main

if __name__ == "__main__":
    raise SystemExit(main())
