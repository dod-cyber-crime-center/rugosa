
from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Optional

import rugosa

from dragodis.ghidra import GhidraLocal
from ghidra.util import Swing
from jpype import JImplements, JOverride
from rugosa.emulation.cpu_context import ProcessorContext


if TYPE_CHECKING:
    from ghidra.program.model.listing import Program
    from ghidra.program.util import ProgramLocation
    from ghidra.program.model.address import Address
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


class ProgramEmulationHelper:

    def __init__(self, program: Program):
        self._program = program
        self._dis = None
        self.emulator: rugosa.Emulator = None
        self.ctx: Optional[ProcessorContext] = None

    @property
    def dis(self) -> GhidraLocal:
        if self._dis is None:
            # lazy initialization
            self._dis = GhidraLocal(currentProgram=self._program)
            self.emulator = rugosa.Emulator(self._dis)
        return self._dis


@JImplements("dc3.rugosa.plugin.RugosaProgramListener")
class ProgramListener:

    def __init__(self, form: EmulatorForm):
        self.form = form
        self.currentProgram: Program = None
        self.location: ProgramLocation = None
        self.emulators: Dict[Program, ProgramEmulationHelper] = {}

    @JOverride
    def programOpened(self, program: Program):
        self.emulators[program] = ProgramEmulationHelper(program)

    @JOverride
    def programClosed(self, program: Program):
        helper = self.emulators.get(program, None)
        if helper is None:
            return
        helper.dis.stop()
        del self.emulators[program]

    @JOverride
    def programActivated(self, program: Program):
        self.currentProgram = program
        Swing.runIfSwingOrRunLater(self.form.update)

    @JOverride
    def programDeactivated(self, program: Program):
        self.currentProgram = None
        Swing.runIfSwingOrRunLater(self.form.update)

    @JOverride
    def locationChanged(self, loc: ProgramLocation):
        self.location = loc

    @property
    def currentAddress(self) -> Address:
        if self.location:
            return self.location.getAddress()
        return Address.NO_ADDRESS

    @property
    def state(self) -> ProgramEmulationHelper:
        if self.currentProgram is None:
            return None
        return self.emulators[self.currentProgram]
