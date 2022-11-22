"""
Script to install IDA plugin.
"""

import pathlib
import shutil
import sys

from .util import get_ida_user_dir


if __name__ == "__main__":
    ida_dir = get_ida_user_dir()
    if not ida_dir:
        print("Unable to find IDA user directory.")
        sys.exit(1)
    entry_point = pathlib.Path(__file__).parent / "rugosa.py"
    destination = ida_dir / "plugins" / "rugosa.py"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(entry_point, destination)
    print(f"Added {destination}")
