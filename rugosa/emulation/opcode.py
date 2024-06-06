import functools

from .registry import registrar


def opcode(name: str = None):
    """
    A decorator for registering opcodes.

    :param name: The builtin function name.
        (Defaults to the name of the decorated function)

    :return: The decorated function.
    :raises ValueError: If the opcode name has already been registered.
    """


def opcode_registrar(registry):
    """
    Creates and returns an opcode decorator.

    :param registry: Dictionary to add opcode registrations to.
    
    :return: The opcode decorator.
    """
    decorator = registrar(registry, name="opcode")
    return functools.wraps(opcode)(decorator)
    
    
