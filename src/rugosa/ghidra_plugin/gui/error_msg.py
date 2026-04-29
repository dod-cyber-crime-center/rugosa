import functools
import logging
import traceback

import jpype

logger = logging.getLogger(__name__)


def show_exception(exception: Exception, title="Error", level=logging.ERROR):
    """
    Shows exception in dialog box.
    """
    # Show error in console.
    logger.log(level, exception, exc_info=level > logging.WARNING)
    # Also show a popup dialog.
    details = str(exception)
    plugin = jpype.JClass("dc3.rugosa.plugin.RugosaPlugin")
    from ghidra.util import Msg
    if level <= logging.INFO:
        Msg.showInfo(plugin, None, title, details)
    elif level <= logging.WARNING:
        Msg.showWarn(plugin, None, title, details)
    else:
        # Show full traceback on error.
        details = "".join(traceback.format_tb(exception.__traceback__)) + f"\n{details}"
        Msg.showError(plugin, None, title, details)


def catch_errors(func):
    """
    Wraps a function to ensure any uncaught exceptions get shown as an error message
    in the Ghidra GUI instead of being thrown.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            show_exception(e)
    return wrapper
