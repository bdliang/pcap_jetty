package pcap.task;

import java.util.concurrent.TimeUnit;

public abstract class AbstractTask implements Runnable {

    private String taskName;

    private long initialDelay;
    private long period;
    private TimeUnit timeUnit;

    public AbstractTask() {
        this("", 2, 2, TimeUnit.SECONDS);
    }

    public AbstractTask(String name) {
        this(name, 2, 2, TimeUnit.SECONDS);
    }

    public AbstractTask(String name, long initialDelay, long period, TimeUnit unit) {
        taskName = name;
        this.initialDelay = initialDelay;
        this.period = period;
        this.timeUnit = unit;
    }

    public String getTaskName() {
        return taskName;
    }

    public void setInitialDelay(long initialDelay) {
        this.initialDelay = initialDelay;
    }

    public long getInitialDelay() {
        return initialDelay;
    }

    public void setPeriod(long period) {
        this.period = period;
    }

    public long getPeriod() {
        return period;
    }

    public void setTimeUnit(TimeUnit unit) {
        this.timeUnit = unit;
    }

    public TimeUnit getTimeUnit() {
        return timeUnit;
    }

}
