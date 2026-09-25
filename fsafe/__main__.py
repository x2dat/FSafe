"""`python -m fsafe` → run the fsafe CLI."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
