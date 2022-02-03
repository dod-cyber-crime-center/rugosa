"""
Import built-in function code based on input file.

These functions are used to emulate the effects of known builtin functions.

Add any builtin functions that need to be handled below.  The function should be declared as such

# Using the same function for multiple instructions:
@builtin_func("memmove")
@builtin_func("memcpy")
def _memcpy(cpu_context, call_ip, func_name, func_args):
    print "IN memmove or memcpy"
    return 1  # Return anything to be placed into rax (or equivalent)

# Using a single function for a builtin
@builtin_func
def memmove(cpu_context, call_ip, func_name, func_args):
    print "IN memmove"

"""

from ..registry import registrar

# Dictionary containing builtin function names -> function
BUILTINS = {}

# Dictionary containing builtin function names -> function
builtin_func = registrar(BUILTINS, name="builtin")


from . import stdlib

# TODO: We shouldn't be determining what global callhooks are available by import.
#   Instead generate a function that will produce the correct callhooks based
#   on the libraries detected in the disassembler.
#   Import based code flow is a no-no

# For now, import WinAPI always.
from . import win_api

# # TODO: Call the framework file type information rather than the IDA functions.
# import idc
#
# file_type = idc.get_inf_attr(idc.INF_FILETYPE)
# if file_type == idc.FT_PE:
#     from . import win_api
# elif file_type == idc.FT_ELF:
#     pass
