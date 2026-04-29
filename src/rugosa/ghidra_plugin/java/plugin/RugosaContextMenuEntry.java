package dc3.rugosa.plugin;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.GTable;

class RugosaContextMenuEntry extends DockingAction {

	private final RugosaDockingAction action;

	RugosaContextMenuEntry(String owner, String name, RugosaDockingAction action) {
		super(name, owner);
		this.action = action;
		setPopupMenuData(new MenuData(new String[]{name}));
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return action.isAddToPopup(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		action.actionPerformed(context);
	}
}
