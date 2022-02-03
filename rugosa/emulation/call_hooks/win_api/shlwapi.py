"""
Functions found in shlwapi.dll

Shell Lightweight Utility Functions
"""
import logging
import ntpath

from ...call_hooks import builtin_func


logger = logging.getLogger(__name__)


@builtin_func("PathAppendA")
@builtin_func("PathAppendW")
#typedef(BOOL PathAppendA(LPSTR  pszPath,LPCSTR pszMore);)
def pathappend(cpu_context, func_name, func_args):
    """
    Appends one path to the end of another
    """
    wide = func_name.endswith(u"W")
    path_ptr, more_ptr = func_args

    curr_path = cpu_context.memory.read_string(path_ptr, wide=wide)
    more_path = cpu_context.memory.read_string(more_ptr, wide=wide)

    full_path = ntpath.join(curr_path, more_path)
    cpu_context.memory.write_string(path_ptr, full_path, wide=wide)
    return True
