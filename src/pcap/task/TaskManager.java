package pcap.task;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class TaskManager {
    private ScheduledExecutorService service;

    public TaskManager() {
        this(10);
    }

    public TaskManager(int num) {
        if (num <= 0)
            num = 10;
        service = Executors.newScheduledThreadPool(num);
    }

    /**
     * 定时执行。 是指，隔 xxx 时间执行一次任务， 与任务的执行时间无关。
     * */
    public void addPeriodTaskAt(AbstractTask task) {
        if (null == task)
            return;

        // System.out.println(task.getTaskName() + " " + task.getInitialDelay()
        // + " " + task.getPeriod());
        service.scheduleAtFixedRate(task, task.getInitialDelay(), task.getPeriod(), task.getTimeUnit());
    }

    /**
     * 定时执行。 是指，这个任务执行完之后，隔 xxx 时间再执行。
     * */
    public void addPeriodTaskWith(AbstractTask task) {
        if (null == task)
            return;

        // System.out.println(task.getTaskName() + " " + task.getInitialDelay()
        // + " " + task.getPeriod());
        service.scheduleWithFixedDelay(task, task.getInitialDelay(), task.getPeriod(), task.getTimeUnit());
    }

    public void addOnceTask(Runnable task, int initialDelay, TimeUnit unit) {
        if (null == task)
            return;
        service.schedule(task, initialDelay, unit);
    }
}
