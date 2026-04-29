
from __future__ import annotations
import logging

from rugosa.emulation.cpu_context import ProcessorContext
from rugosa.emulation.instruction import Instruction
from rugosa.emulation.monitor import Monitor
from rugosa.strings import DecodedString


logger = logging.getLogger(__name__)
ENCODINGS = [("utf-8", 1), ("utf-16-le", 2)]


class StackStringsMonitor(Monitor):
    """
    Extracts contents of stack string variables.
    """

    ENCODINGS = [("utf-8", 1), ("utf-16-le", 2)]

    def __init__(self, min_length: int = 3):
        self._min_length = min_length
        self._decoded_strings = []
        self._waiting_for_call = []

    def clear(self):
        self._decoded_strings.clear()
        self._waiting_for_call.clear()

    def __iter__(self) -> DecodedString:
        self._cleanup()
        for _, string in self._decoded_strings:
            yield string

    def _process_waiting_for_call(self, context):
        """
        Processes the stack variables waiting for a call instruction (or function termination)
        """
        for ip, var in self._waiting_for_call:
            if string := self._search_stack(context, var, ip):
                self._decoded_strings.append(string)
        self._waiting_for_call = []

    @staticmethod
    def _num_raw_bytes(string: str) -> int:
        """
        Returns the number of raw bytes found in the given unicode string
        """
        count = 0
        for char in string:
            char = char.encode("unicode-escape")
            count += char.startswith(b"\\x") + char.startswith(b"\\u") * 2
        return count

    def _read_string(self, stream):
        """
        Read data until we find a something that is not a printable ascii character.

        :return: String and encoding if we find a string of at least 1 character.
            Returns Nones otherwise.
        """
        strings = []
        for encoding, width in self.ENCODINGS:
            stream.seek(0)
            chars = []
            while True:
                char = stream.read(width)
                if not char:
                    # Ran out of bytes
                    break
                try:
                    char = char.decode(encoding)
                except UnicodeDecodeError:
                    break
                if char == "\0" or self._num_raw_bytes(char):
                    break
                chars.append(char)
            if chars:
                string = "".join(chars)
                strings.append((string, encoding))

        if not strings:
            return None, None

        # Return whichever encoding uses the most data.
        return max(strings, key=lambda s: len(s[0]))

    def _search_stack(self, context, var, ip) -> Optional[tuple[int, DecodedString]]:
        """
        Searches through the data on the stack and checks for valid strings
        """
        if context.memory.is_mapped(var.addr):
            with context.memory.open(var.addr) as stack_stream:
                string, encoding = self._read_string(stack_stream)
            if string:
                data = string.encode(encoding)
                # TODO: This isn't right, fixup.
                decoded_string = DecodedString(data, encoding=encoding, enc_source=var.static, dec_source=ip)
                return var.addr, decoded_string

    def _cleanup(self):
        """
        Cleans up decoded strings:
            - Removes strings that are just a substring of another.
            - Deduplicates
            - Removes strings less than minimum length.
        """
        # TODO: Simplify if slow.
        # Remove any substrings or strings that are too small.
        decoded_strings = self._decoded_strings
        for op_addr, decoded_string in decoded_strings[:]:
            if len(decoded_string.data) < self._min_length:
                decoded_strings.remove((op_addr, decoded_string))
                continue
            for _addr, _decoded_string in decoded_strings[:]:
                # Remove dups
                if (
                        _addr == op_addr
                        and _decoded_string is not decoded_string
                        and _decoded_string.data == decoded_string.data
                ):
                    decoded_strings.remove((op_addr, decoded_string))
                    break
                # Remove substrings
                if _addr < op_addr:
                    index = op_addr - _addr
                    substring = _decoded_string.data[index: index + len(decoded_string.data)]
                    if substring == decoded_string.data:
                        decoded_strings.remove((op_addr, decoded_string))
                        break

    def post_instruction(self, context: ProcessorContext, instruction: Instruction):
        # If we encounter a call, process pushed in variables.
        if instruction.mnemonic == "call":
            self._process_waiting_for_call(context)
            return

        # Look for instructions where a stack variable is being used for something other than
        # a move.
        # We can do this by only considering variables that are the last operand.
        operands = instruction.operands
        if not operands:
            return
        operand = operands[-1]
        op_addr = operand.addr or operand.value
        if not op_addr:
            return
        var = context.variables.get(op_addr)
        if var and var.is_stack:
            # Ignore string if it comes from memory with no concatenations.
            history = var.history
            if history and context.disassembler.is_loaded(history[0].addr):
                return

            # If instruction is a push, it is possible that the string will be populated
            # after this instruction. Therefore, wait for the function call be before processing.
            if instruction.mnemonic == "push":
                self._waiting_for_call.append((instruction.ip, var))
            elif string := self._search_stack(context, var, instruction.ip):
                self._decoded_strings.append(string)

    def code_path_end(self, context: ProcessorContext, instruction: Instruction):
        # Perform a final pass on all the variables in the function's stack frame.
        if function := context.disassembler.get_function(instruction.ip, None):
            for stack_var in function.stack_frame:
                if var := context.variables.get(stack_var.name):
                    if string := self._search_stack(context, var, instruction.ip):
                        self._decoded_strings.append(string)

        # Process pending stack variables.
        self._process_waiting_for_call(context)
