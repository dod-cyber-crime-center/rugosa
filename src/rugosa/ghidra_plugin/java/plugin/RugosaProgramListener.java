package dc3.rugosa.plugin;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public interface RugosaProgramListener {

	default void programOpened(Program program) {
	}
	default void programClosed(Program program) {
	}
	default void programActivated(Program program) {
	}
	default void programDeactivated(Program program) {
	}
	default void locationChanged(ProgramLocation loc) {
	}
}
