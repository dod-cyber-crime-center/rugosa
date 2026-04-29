package dc3.rugosa.plugin;

import javax.swing.*;

import docking.ComponentProvider;


public class RugosaComponentProvider extends ComponentProvider {

    private final EmulatorForm form;

    public RugosaComponentProvider(RugosaPlugin plugin, String owner) {
        super(plugin.getTool(), "Rugosa Emulator", owner);
        form = new EmulatorForm();
    }

    EmulatorForm getForm() {
        return form;
    }

    @Override
    public JComponent getComponent() {
        return form.mainPanel;
    }
}
