"""
Rugosa IDA Plugin.
"""

import ida_idaapi

import dragodis

import rugosa
from rugosa.ida_plugin.components.emulator import EmulatorForm


class RugosaPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Rugosa"
    help = "See https://github.com/dod-cyber-crime-center/rugosa/blob/master/readme.md"
    wanted_name = "Rugosa Emulator"
    wanted_hotkey = "Ctrl-Alt-R"

    def init(self):
        """Called when plugin is initially loaded."""
        print(
            f"-------------------------------\n"
            f"Rugosa Emulator\n"
            f"rugosa v{rugosa.__version__}, dragodis v{dragodis.__version__}\n"
            f"-------------------------------\n"
        )
        self.form = None
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        """Starts the plugin."""
        if not self.form:
            self.form = EmulatorForm(dragodis.IDA())
        self.form.Show(self.wanted_name)

    def term(self):
        ...
