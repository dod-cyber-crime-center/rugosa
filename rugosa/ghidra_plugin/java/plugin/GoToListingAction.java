package dc3.rugosa.plugin;

import java.awt.Point;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.GTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

class GoToListingAction extends DockingAction {

	private final RugosaPlugin plugin;

	GoToListingAction(RugosaPlugin plugin) {
		super("Navigation", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[]{"Goto Address"}));
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		Address address = getSelectedTableAddress(context);
		if (address == null) {
			return false;
		}
		return plugin.getCurrentProgram().getMemory().contains(address);
	}

	private Address getSelectedTableAddress(ActionContext context) {
		Object source = context.getMouseEvent().getSource();
		if (source instanceof GTable) {
			GTable table = (GTable) source;
			Point point = context.getMouseEvent().getPoint();
			int row = table.rowAtPoint(point);
			int column = table.columnAtPoint(point);
			Object value = table.getValueAt(row, column);
			if (value instanceof String) {
				AddressFactory factory = plugin.getCurrentProgram().getAddressFactory();
				return factory.getAddress((String)value);
			}
		}
		return null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.goTo(getSelectedTableAddress(context));
	}
}
