
import os
import pathlib
import sys
from typing import Optional


def get_ida_user_dir() -> Optional[pathlib.Path]:
    """
    Attempts to get the user directory for IDA.
    """
    # First check if IDAUSR has been set.
    path = os.getenv("IDAUSR")
    if path:
        return pathlib.Path(path)

    # Otherwise obtain path from preset based on IDA documentation.
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA")
        if not appdata:
            return None
        return pathlib.Path(appdata, "Hex-Rays", "IDA Pro")
    else:
        return pathlib.Path("~", ".idapro").expanduser()
