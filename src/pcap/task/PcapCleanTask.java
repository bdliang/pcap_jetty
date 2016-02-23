package pcap.task;

import pcap.table.TcpTable;
import pcap.table.UrlTable;

import java.util.concurrent.TimeUnit;

public class PcapCleanTask extends AbstractTask {

    /**
     * 目前定义 每60秒执行一次
     * */

    public PcapCleanTask() {
        this(60, 60, TimeUnit.SECONDS);
    }

    public PcapCleanTask(String name) {
        this(name, 60, 60, TimeUnit.SECONDS);
    }
    public PcapCleanTask(long initialDelay, long period, TimeUnit unit) {
        super("", initialDelay, period, unit);
    }

    public PcapCleanTask(String name, long initialDelay, long period, TimeUnit unit) {
        super(name, initialDelay, period, unit);
    }

    @Override
    public void run() {
        TcpTable.getInstance().clean();
        UrlTable.getInstance().clean();
    }
}
