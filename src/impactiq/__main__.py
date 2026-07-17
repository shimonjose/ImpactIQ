"""Enable `python -m impactiq`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
