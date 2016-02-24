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

    private boolean tableSwitch;

    public PcapCleanTask() {
        this(DEFAULT_CLEAN_DELAY, DEFAULT_CLEAN_INTERVAL, TimeUnit.SECONDS, false);
    }

    public PcapCleanTask(String name) {
        this(name, DEFAULT_CLEAN_DELAY, DEFAULT_CLEAN_INTERVAL, TimeUnit.SECONDS, false);
    }

    public PcapCleanTask(boolean tableSwitch) {
        this(DEFAULT_CLEAN_DELAY, DEFAULT_CLEAN_INTERVAL, TimeUnit.SECONDS, tableSwitch);
    }

    public PcapCleanTask(long initialDelay, long period, TimeUnit unit, boolean tableSwitch) {
        super("", initialDelay, period, unit);
        this.tableSwitch = tableSwitch;
    }

    public PcapCleanTask(String name, long initialDelay, long period, TimeUnit unit, boolean tableSwitch) {
        super(name, initialDelay, period, unit);
        this.tableSwitch = tableSwitch;
    }

    public boolean isCleanSwitch() {
        return tableSwitch;
    }

    public void setCleanSwitch(boolean tableSwitch) {
        this.tableSwitch = tableSwitch;
    }

    @Override
    public void run() {
        if (tableSwitch) {
            TcpTable.getInstance().tableSwitch();
            // UrlTable.getInstance().tableSwitch();
            // MysqlServerTable.getInstance().tableSwitch();
        } else {
            TcpTable.getInstance().clean();
            UrlTable.getInstance().clean();
            MysqlServerTable.getInstance().clean();
        }
    }
}
