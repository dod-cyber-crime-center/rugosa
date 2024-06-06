package dc3.rugosa.plugin;

import java.util.function.BiConsumer;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;


@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Rugosa Emulator Plugin",
	description = "GUI for the Rugosa emulation utility. (Requires Ghidra started with pyhidraw launcher.)"
)
public final class RugosaPlugin extends ProgramPlugin {

	private static final RugosaProgramListener DEFAULT_LISTENER =
		new RugosaProgramListener(){};
	private static BiConsumer<EmulatorForm, RugosaPlugin> initializer = null;

	private RugosaComponentProvider provider;
	private RugosaProgramListener programListener = DEFAULT_LISTENER;

	public RugosaPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();
		provider = new RugosaComponentProvider(this, name);
		tool.addComponentProvider(provider, false);
		if (initializer != null) {
			initializer.accept(provider.getForm(), this);
		}
	}

	public static void setInitiailizer(BiConsumer<EmulatorForm, RugosaPlugin> initializer) {
		if (RugosaPlugin.initializer != null) {
			throw new RuntimeException("RugosaPlugin.initializer cannot be changed");
		}
		RugosaPlugin.initializer = initializer;
	}

	public void setProgramListener(RugosaProgramListener programListener) {
		if (this.programListener != DEFAULT_LISTENER) {
			throw new RuntimeException("programListener cannot be changed");
		}
		this.programListener = programListener;
	}

	@Override
	protected void programActivated(Program program) {
		programListener.programActivated(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		programListener.programDeactivated(program);
	}

	@Override
	protected void programOpened(Program program) {
		programListener.programOpened(program);
	}

	@Override
	protected void programClosed(Program program) {
		programListener.programClosed(program);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		programListener.locationChanged(loc);
	}

	public void addContextMenuEntry(String name_, RugosaDockingAction action) {
		provider.addLocalAction(new RugosaContextMenuEntry(name, name_, action));
	}

	public Address getCurrentAddress() {
		return currentLocation != null ? currentLocation.getAddress() : null;
	}

	@Override
	public boolean goTo(Address address) {
		return super.goTo(address);
	}
}
