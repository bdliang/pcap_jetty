package pcap.task;

import pcap.table.MysqlServerTable;
import pcap.table.TcpTable;
import pcap.table.UrlTable;

import java.util.concurrent.TimeUnit;

public class PcapCleanTask extends AbstractTask {

    /** 默认30s后开始执行 */
    private static int DEFAULT_CLEAN_DELAY = 30; // 单位是 秒
    /** 默认 每30秒执行一次 */
    private static int DEFAULT_CLEAN_INTERVAL = 30; // 单位是 秒

    public PcapCleanTask() {
        this(DEFAULT_CLEAN_DELAY, DEFAULT_CLEAN_INTERVAL, TimeUnit.SECONDS);
    }

    public PcapCleanTask(String name) {
        this(name, DEFAULT_CLEAN_DELAY, DEFAULT_CLEAN_INTERVAL, TimeUnit.SECONDS);
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
        MysqlServerTable.getInstance().clean();
    }
}
