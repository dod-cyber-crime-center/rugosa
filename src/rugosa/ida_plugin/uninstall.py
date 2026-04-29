"""
Script to uninstall IDA plugin.
"""

import sys

from .util import get_ida_user_dir


if __name__ == "__main__":
    ida_dir = get_ida_user_dir()
    if not ida_dir:
        print("Unable to find IDA user directory.")
        sys.exit(1)
    entry_point = ida_dir / "plugins" / "rugosa.py"
    if entry_point.exists():
        entry_point.unlink()
        print(f"Removed {entry_point}")
    else:
        print("Already removed.")
