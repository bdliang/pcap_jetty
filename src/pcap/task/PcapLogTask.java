package pcap.task;

import pcap.table.TcpTable;
import pcap.table.UrlTable;

import java.util.concurrent.TimeUnit;

public class PcapLogTask extends AbstractTask {

    public PcapLogTask() {
        this(60, 60, TimeUnit.SECONDS);
    }

    public PcapLogTask(String name) {
        this(name, 60, 60, TimeUnit.SECONDS);
    }
    public PcapLogTask(long initialDelay, long period, TimeUnit unit) {
        super("", initialDelay, period, unit);
    }

    public PcapLogTask(String name, long initialDelay, long period, TimeUnit unit) {
        super(name, initialDelay, period, unit);
    }

    @Override
    public void run() {
        TcpTable.getInstance().dumpToFile();
        UrlTable.getInstance().dumpToFile();
    }

}
