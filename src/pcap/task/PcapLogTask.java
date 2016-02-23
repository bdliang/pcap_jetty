package pcap.task;

import pcap.table.MysqlServerTable;
import pcap.table.TcpTable;
import pcap.table.UrlTable;

import java.util.concurrent.TimeUnit;

public class PcapLogTask extends AbstractTask {

    /** 默认30s后开始执行 */
    private static int DEFAULT_LOG_DELAY = 5; // 单位是 秒
    /** 默认 每30秒执行一次 */
    private static int DEFAULT_LOG_INTERVAL = 5; // 单位是 秒

    public PcapLogTask() {
        this(DEFAULT_LOG_DELAY, DEFAULT_LOG_INTERVAL, TimeUnit.SECONDS);
    }

    public PcapLogTask(String name) {
        this(name, DEFAULT_LOG_DELAY, DEFAULT_LOG_INTERVAL, TimeUnit.SECONDS);
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
        MysqlServerTable.getInstance().dumpToFile();
    }

}
