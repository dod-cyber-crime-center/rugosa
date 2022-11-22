"""
Entrypoint for the Rugosa IDA Plugin.
"""

from rugosa.ida_plugin.plugin import RugosaPlugin


def PLUGIN_ENTRY():
    return RugosaPlugin()


if __name__ == "__main__":
    # If user is running this like a script directly start it up.
    plugin = PLUGIN_ENTRY()
    plugin.init()
    plugin.run()
