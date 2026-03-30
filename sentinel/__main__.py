"""
sentinel package entry point.

Allows running the CLI directly with:
    python -m sentinel build  --evtx <folder> --output <dir>
    python -m sentinel analyze --evtx <files> --baseline <dir>
"""
from sentinel.cli import main
import sys

sys.exit(main())
