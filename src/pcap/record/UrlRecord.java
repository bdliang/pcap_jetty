package pcap.record;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;

import java.util.HashMap;
import java.util.Map;

public class UrlRecord {

    // 用于转化json时字段控制
    public static final JsonConfig config = new JsonConfig();
    static {
        config.setExcludes(null);
    }

    private int ip;
    private int port;
    private String url;

    private long totalTime;
    private long totalCount;
    private Map<HttpItems, Integer> counters;

    private long lastTimeStamp;
    private long lastTime;

    public long getLastTimeStamp() {
        return lastTimeStamp;
    }

    public long getLastTime() {
        return lastTime;
    }

    public long getTotalTime() {
        return totalTime;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public UrlRecord(int ip, int port, String url) {
        this.ip = ip;
        this.port = port;
        this.url = url;

        totalTime = 0L;
        totalCount = 0L;
        counters = new HashMap<UrlRecord.HttpItems, Integer>();
        lastTimeStamp = 0L;
        lastTime = 0L;
    }

    public void addTimeRecord(long time) {
        this.totalTime += time;
        ++this.totalCount;
    }

    public void addTimeRecord(long time, long lastTimeStamp) {
        if (time <= 0)
            return;
        this.totalTime += time;
        ++this.totalCount;

        if (this.lastTimeStamp >= 0 && this.lastTimeStamp < lastTimeStamp) {
            this.lastTimeStamp = lastTimeStamp;
            this.lastTime = time;
        }
    }

    public int getItemCount(HttpItems item) {
        if (null == item || HttpItems.OTHER == item)
            return 0;
        Integer cnt = counters.get(item);
        if (null == cnt) {
            cnt = 0;
        }
        return cnt;
    }

    public int getItemCount(String str) {
        return getItemCount(HttpItems.parseContentType(str));
    }

    public void addItem(HttpItems item) {
        if (null == item || HttpItems.OTHER == item)
            return;
        Integer tmp = counters.get(item);
        if (null == tmp) {
            counters.put(item, 1);
        } else {
            counters.put(item, 1 + tmp);
        }
    }

    public void addItem(String str) {
        addItem(HttpItems.parseContentType(str));
    }

    public double avgTime() {
        if (0 == totalCount)
            return 0.0;
        else
            return (totalTime * 1.0) / totalCount;
    }

    public String getUrl() {
        return url;
    }

    public int getIp() {
        return ip;
    }

    public int getPort() {
        return port;
    }

    public Map<HttpItems, Integer> getCounters() {
        return counters;
    }

    public enum HttpItems {
        GET("GET"), POST("POST"), HEAD("HEAD"), PUT("PUT"), DELETE("DELETE"), OPTIONS("OPTIONS"), TRACE("TRACE"), CONNECT("CONNECT"), XX2(
                "200"), _302("302"), _304("304"), _403("403"), _404("404"), _500("500"), _501("501"), _503("503"), OTHER, ;

        private String desc;

        private HttpItems(String desc) {
            this.desc = desc;
        }
        private HttpItems() {
            desc = "";
        }
        public String getDesc() {
            return desc;
        }

        public static HttpItems parseContentType(String type) {
            if (null == type) {
                return OTHER;
            }
            for (HttpItems t : values()) {
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
