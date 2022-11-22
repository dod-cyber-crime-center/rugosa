package dc3.rugosa.plugin;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class RugosaTask extends Task {

    Runnable runnable;

    public RugosaTask(String title, Runnable runnable) {
        super(title, false, false, true, true);
        this.runnable = runnable;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        runnable.run();
    }
}
