package pcap.record;

import java.util.HashMap;
import java.util.Map;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;

/**
 * 用于记录Mysql的统计信息， 以mysql服务器为单位
 * 
 */

public class MysqlServerRecord {

    // 用于转化json时字段控制
    public static final JsonConfig config = new JsonConfig();
    static {
        config.setExcludes(null);
    }

    private int ip;
    private int port;

    private long totalTime;
    private long totalCount;
    private Map<MysqlItems, Integer> counters;

    public MysqlServerRecord(int ip, int port) {
        this.ip = ip;
        this.port = port;

        totalTime = 0L;
        totalCount = 0L;
        counters = new HashMap<MysqlItems, Integer>();
    }

    public void addTimeRecord(long time) {
        if (time <= 0)
            return;
        this.totalTime += time;
        ++this.totalCount;
    }

    public void addItem(MysqlItems item) {
        if (null == item || MysqlItems.OTHER == item)
            return;
        Integer tmp = counters.get(item);
        if (null == tmp) {
            counters.put(item, 1);
        } else {
            counters.put(item, 1 + tmp);
        }
    }

    public void addItem(String str) {
        addItem(MysqlItems.parseContentType(str));
    }

    public int getItemCount(MysqlItems item) {
        if (null == item || MysqlItems.OTHER == item)
            return 0;
        Integer cnt = counters.get(item);
        if (null == cnt) {
            cnt = 0;
        }
        return cnt;
    }

    public double avgTime() {
        if (0 == totalCount)
            return 0.0;
        else
            return (totalTime * 1.0) / totalCount;
    }

    /** getter & setter */
    public int getIp() {
        return ip;
    }

    public int getPort() {
        return port;
    }

    public long getTotalTime() {
        return totalTime;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public Map<MysqlItems, Integer> getCounters() {
        return counters;
    }
    /** getter & setter */

    public enum MysqlItems {
        SELECT("SELECT"), UPDATE("UPDATE"), INSERT("INSERT"), DELETE("DELETE"), COMMIT("COMMIT"), ROLLBACK("ROLLBACK"), ERROR(
                "ERROR"), OTHER,;

        private String desc;

        private MysqlItems(String desc) {
            this.desc = desc;
        }
        private MysqlItems() {
            desc = "";
        }
        public String getDesc() {
            return desc;
        }

        public static MysqlItems parseContentType(String type) {
            if (type == null) {
                return OTHER;
            }

            for (MysqlItems t : values()) {
                if (t.name().equalsIgnoreCase(type)) {
                    return t;
                }
            }

            return OTHER;
        }
    }

    @Override
    public String toString() {
        return JSONObject.fromObject(this).toString();
    }

}
