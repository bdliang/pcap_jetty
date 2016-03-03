package pcap.record;

import java.util.HashMap;
import java.util.Map;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;

public class MongoDBCollectionRecord {

    public static final JsonConfig config = new JsonConfig();
    static {
        config.setExcludes(null);
    }

    private int ip;
    private int port;

    private long totalTime;
    private long totalCount;
    private Map<MongoDBItems, Integer> counters;
    private String tableName;

    @Deprecated
    public MongoDBCollectionRecord(int ip, int port) {
        super();
        this.ip = ip;
        this.port = port;
        this.counters = new HashMap<MongoDBItems, Integer>();
        this.totalTime = 0;
        this.totalCount = 0;
        this.tableName = "";
    }

    public MongoDBCollectionRecord(int ip, int port, String name) {
        super();
        this.ip = ip;
        this.port = port;
        this.counters = new HashMap<MongoDBItems, Integer>();
        this.totalTime = 0;
        this.totalCount = 0;
        this.tableName = name;
    }

    public void addTimeRecord(long time) {
        if (time <= 0)
            return;
        this.totalTime += time;
        ++this.totalCount;
    }

    public void addItem(MongoDBItems item) {
        if (null == item || MongoDBItems.OTHER == item)
            return;
        Integer tmp = counters.get(item);
        if (null == tmp) {
            counters.put(item, 1);
        } else {
            counters.put(item, 1 + tmp);
        }
    }

    public void addItem(String str) {
        addItem(MongoDBItems.parseContentType(str));
    }

    public int getItemCount(MongoDBItems item) {
        if (null == item || MongoDBItems.OTHER == item)
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

    public Map<MongoDBItems, Integer> getCounters() {
        return counters;
    }

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }
    /** getter & setter */

    public enum MongoDBItems {
        FIND("FIND"), UPDATE("UPDATE"), INSERT("INSERT"), DELETE("DELETE"), GETMORE("GETMORE"), ISMASTER("ISMASTER"), ERROR(
                "ERROR"), KILL_CURSORS("KILL_CURSORS"), OTHER,;

        private String desc;

        private MongoDBItems(String desc) {
            this.desc = desc;
        }
        private MongoDBItems() {
            desc = "";
        }
        public String getDesc() {
            return desc;
        }

        public static MongoDBItems parseContentType(String type) {
            if (type == null) {
                return OTHER;
            }

            for (MongoDBItems t : values()) {
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
