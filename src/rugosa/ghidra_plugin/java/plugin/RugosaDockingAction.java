package dc3.rugosa.plugin;

import docking.ActionContext;

public interface RugosaDockingAction {

	public boolean isAddToPopup(ActionContext context);

	public void actionPerformed(ActionContext context);
}
