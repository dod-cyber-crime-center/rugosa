
from pathlib import Path

import pyhidra

from rugosa import __version__
from jpype.types import JClass


def setup(launcher):
    """
    Run by pyhidra launcher to install our plugin.
    """
    source_path = Path(__file__).parent / "java" / "plugin"
    details = pyhidra.ExtensionDetails(
        name="rugosa",
        description="Rugosa Emulator Plugin",
        author="Department of Defence Cyber Crime Center (DC3)",
        plugin_version=__version__,
    )
    launcher.install_plugin(source_path, details)


def pre_launch():
    # rugosa classes might not exist when this module is imported
    # the emulator functions must be imported here
    from java.lang import ClassLoader
    from rugosa.ghidra_plugin.components.emulator import initialize

    gcl = ClassLoader.getSystemClassLoader()
    RugosaPlugin = JClass("dc3.rugosa.plugin.RugosaPlugin", loader=gcl)
    RugosaPlugin.setInitiailizer(initialize)
