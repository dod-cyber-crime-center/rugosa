package dc3.rugosa.plugin;

import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import docking.widgets.label.GDLabel;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

class RugosaTabbedPane extends JTabbedPane implements MouseListener {

	RugosaTabbedPane() {
		super();
	}

	RugosaTabbedPane(int tabPlacement) {
		super(tabPlacement);
	}

	RugosaTabbedPane(int tabPlacement, int tabLayoutPolicy) {
		super(tabPlacement, tabLayoutPolicy);
	}

	@Override
	public void addTab(String title, Component component) {
		GDLabel label = new GDLabel();
		label.setText(title);
		label.addMouseListener(this);
		int index = getTabCount();
		insertTab(title, null, component, null, index);
		setTabComponentAt(index, label);
	}

	private void forwardEvent(MouseEvent e) {
		MouseEvent newEvent = SwingUtilities.convertMouseEvent(e.getComponent(), e, this);
		dispatchEvent(newEvent);
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		forwardEvent(e);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		forwardEvent(e);
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		forwardEvent(e);
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		forwardEvent(e);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		forwardEvent(e);
	}

}
