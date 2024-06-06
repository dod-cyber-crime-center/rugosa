"""
Import built-in function code based on input file.

These functions are used to emulate the effects of known builtin functions.

Add any builtin functions that need to be handled below.  The function should be declared as such

# Using the same function for multiple instructions:
@builtin_func("memmove")
@builtin_func("memcpy")
def _memcpy(cpu_context, call_ip, func_name, func_args):
    print("IN memmove or memcpy")
    return 1  # Return anything to be placed into rax (or equivalent)

# Using a single function for a builtin
@builtin_func
def memmove(cpu_context, call_ip, func_name, func_args):
    print("IN memmove")

"""

import functools

# Dictionary containing builtin function names -> function
BUILTINS = {}


# template to use for updating the wrapper doc strings and signature
def builtin_func(entry_name: str = None, /, num_args: int = None):
    """
    A decorator for registering builtin functions.

    :param entry_name: The builtin function name.
        (Defaults to the name of the decorated function)
    :param num_args: Number of arguments the builtin function takes.
        (Defaults to the number of arguments determined by the Disassembler)

    :return: The decorated function.
    
    :raises ValueError: If the builtin function name or number of arguments
        has already been registered or if the number of arguments is less than 0.
    """


def _builtin_func_registrar(registry):    
    
    arg_counts = {}
    
    @functools.wraps(builtin_func)
    def register_args(entry_name_or_func=None, /, num_args: int = None, *, entry_name: str = None):
        
        if not callable(entry_name_or_func):
            # store the name as a keyword argument and bind it and num_args to register_args
            return functools.partial(register_args, num_args=num_args, entry_name=entry_name_or_func)
        
        func = entry_name_or_func
        if not entry_name:
            entry_name = func.__name__
        
        entry_name = entry_name.lower()
        
        if isinstance(num_args, int) and num_args < 0:
            raise ValueError(f"num_args for {entry_name} must be >= 0")
        
        if entry_name in registry:
            raise ValueError(f"Duplicate builtin name: {entry_name}")
        
        if entry_name in arg_counts:
            raise ValueError(f"Duplicate num_args registered for function: {entry_name}")
        
        if num_args is not None:
            # we don't need to add it unless it is actually set
            # num_args may be 0
            arg_counts[entry_name] = num_args
        
        # register the function name and number of arguments
        registry[entry_name] = func
        func.num_args = lambda name: arg_counts.get(name.lower())
        
        return func  # Must return function afterwards.

    return register_args


builtin_func = _builtin_func_registrar(BUILTINS)

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
