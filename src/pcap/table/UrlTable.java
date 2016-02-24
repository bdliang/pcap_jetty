package pcap.table;

import pcap.record.UrlRecord;
import pcap.record.UrlRecord.HttpItems;
import pcap.result.UrlLastTime;
import pcap.utils.BasicUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class UrlTable extends Table<Long, Map<String, UrlRecord>> implements TableAction {

    /**
     * 用来记录url的表
     * 
     * ip, port, url作为主键， UrlRecord 作为值。其中， ip和port拼成long型作为k1, map->
     * Map<String, UrlRecord> 再利用url -> UrlRecord。
     * 
     * 提供整体的和某个ip或某对ip/port或某个url的相关统计和响应时间
     * */
    private static UrlTable single;

    private UrlTable() {
        currentTable = new HashMap<Long, Map<String, UrlRecord>>();
        lastTable = new HashMap<Long, Map<String, UrlRecord>>();
        workingTable = currentTable;
    }

    /* 单例 */
    public static UrlTable getInstance() {
        if (null == single) {
            synchronized (UrlTable.class) {
                if (null == single) {
                    single = new UrlTable();
                }
            }
        }
        return single;
    }

    public int getNum(boolean current) {
        setWorkingTable(current);
        int cnt = 0;
        for (Map<String, UrlRecord> subMap : workingTable.values()) {
            cnt += subMap.size();
        }
        return cnt;
    }

    /**
     * 在UrlTable中， 查找 ip, port, url对应的记录
     * 
     * @return 存在记录则返回该记录；否则新建一个记录加入到表中并返回该记录。如果有不符合条件的，则返回null
     * */
    public UrlRecord getUrlRecord(int ip, int port, String url) {
        UrlRecord record = null;
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(url))
            return null;

        setWorkingTable(true);
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, UrlRecord> subMap = workingTable.get(key);
        if (null == subMap) {
            subMap = new HashMap<String, UrlRecord>();
            record = new UrlRecord(ip, port, url);
            subMap.put(url, record);
            workingTable.put(key, subMap);
        } else {
            record = subMap.get(url);
            if (null == record) {
                record = new UrlRecord(ip, port, url);
                subMap.put(url, record);
            }
        }
        return record;
    }

    /* 整体查找 */
    /**
     * 获得所有item属性的个数
     * */
    public int getCount(HttpItems item, boolean current) {
        if (null == item || HttpItems.OTHER == item)
            return 0;
        setWorkingTable(current);
        int cnt = 0;
        for (Map<String, UrlRecord> subMap : workingTable.values()) {
            for (UrlRecord record : subMap.values()) {
                cnt += record.getItemCount(item);
            }
        }
        return cnt;
    }

    /**
     * 返回所有url的平均响应时间
     * */
    public double getAvgTime(boolean current) {
        setWorkingTable(current);
        long time = 0;
        long cnt = 0;
        for (Map<String, UrlRecord> subMap : workingTable.values()) {
            for (UrlRecord record : subMap.values()) {
                time += record.getTotalTime();
                cnt += record.getTotalCount();
            }
        }
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    /* 根据url查找 */
    public int getCount(String url, HttpItems item, boolean current) {
        setWorkingTable(current);
        if (BasicUtils.isStringBlank(url) || null == item || HttpItems.OTHER == item)
            return 0;
        int cnt = 0;
        for (Map<String, UrlRecord> subMap : workingTable.values()) {
            UrlRecord record = subMap.get(url);
            if (null == record)
                continue;
            cnt += record.getItemCount(item);
        }
        return cnt;
    }

    public double getAvgTimeByUrl(String url, boolean current) {
        setWorkingTable(current);
        long time = 0;
        long cnt = 0;
        for (Map<String, UrlRecord> subMap : workingTable.values()) {
            UrlRecord record = subMap.get(url);
            if (null == record)
                continue;
            time += record.getTotalTime();
            cnt += record.getTotalCount();
        }
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    /* 根据ip查找 */
    public int getCountByIp(int ip, HttpItems item, boolean current) {
        if (null == item || HttpItems.OTHER == item)
            return 0;
        setWorkingTable(current);
        int cnt = 0;
        for (Long ipPort : workingTable.keySet()) {
            if (ip != BasicUtils.getHigh4BytesFromLong(ipPort))
                continue;
            Map<String, UrlRecord> subMap = workingTable.get(ipPort);
            for (UrlRecord record : subMap.values()) {
                cnt += record.getItemCount(item);
            }
        }
        return cnt;
    }

    public double getAvgTimeByIp(int ip, boolean current) {
        setWorkingTable(current);
        long time = 0;
        long cnt = 0;
        for (Long ipPort : workingTable.keySet()) {
            if (ip != BasicUtils.getHigh4BytesFromLong(ipPort))
                continue;
            Map<String, UrlRecord> subMap = workingTable.get(ipPort);
            for (UrlRecord record : subMap.values()) {
                time += record.getTotalTime();
                cnt += record.getTotalCount();
            }
        }
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    /* 根据ip/port查找 */
    public int getCountByIpPort(int ip, int port, HttpItems item, boolean current) {
        if (!BasicUtils.isPortValid(port) || null == item || HttpItems.OTHER == item)
            return 0;
        setWorkingTable(current);
        int cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, UrlRecord> subMap = workingTable.get(key);
        if (null == subMap)
            return 0;
        for (UrlRecord record : subMap.values()) {
            cnt += record.getItemCount(item);
        }
        return cnt;
    }

    public double getAvgTimeByIpPort(int ip, int port, boolean current) {
        if (!BasicUtils.isPortValid(port))
            return 0.0;
        setWorkingTable(current);
        long time = 0;
        long cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, UrlRecord> subMap = workingTable.get(key);
        if (null == subMap)
            return 0.0;
        for (UrlRecord record : subMap.values()) {
            time += record.getTotalTime();
            cnt += record.getTotalCount();
        }
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    /* 根据ip/port/url查找 */
    public int getCountByIpPortUrl(int ip, int port, String url, HttpItems item, boolean current) {
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(url))
            return 0;
        setWorkingTable(current);
        int cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, UrlRecord> subMap = null;
        UrlRecord record = null;
        if (null == (subMap = workingTable.get(key)) || null == (record = subMap.get(url)))
            return 0;
        cnt = record.getItemCount(item);
        return cnt;
    }

    public double getAvgTimeByIpPortUrl(int ip, int port, String url, boolean current) {
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(url))
            return 0.0;
        setWorkingTable(current);
        long time = 0;
        long cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, UrlRecord> subMap = null;
        UrlRecord record = null;
        if (null == (subMap = workingTable.get(key)) || null == (record = subMap.get(url)))
            return 0.0;
        time += record.getTotalTime();
        cnt += record.getTotalCount();
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    public UrlLastTime getLastTimeByIpPortUrl(int ip, int port, String url, boolean current) {
        UrlLastTime re = null;
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(url))
            return null;
        setWorkingTable(current);
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, UrlRecord> subMap = null;
        UrlRecord record = null;
        if (null == (subMap = workingTable.get(key)) || null == (record = subMap.get(url)))
            return null;
        re = new UrlLastTime(record.getLastTimeStamp(), record.getLastTime());
        return re;
    }

    @Override
    public void clean() {
        System.out.println("UrlTable clean");
        for (Map<String, UrlRecord> subMap : lastTable.values()) {
            subMap.clear();
        }
        lastTable.clear();

        for (Map<String, UrlRecord> subMap : currentTable.values()) {
            subMap.clear();
        }
        currentTable.clear();
    }

    @Override
    public void dumpToFile() {
        File file = new File(TableAction.filePath);
        setWorkingTable(true);
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fileWritter = new FileWriter(file.getName(), true);
            BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
            bufferWritter.write("#### Url Record ####\n");
            // Map<Long, Map<String, UrlRecord>> map
            for (Map.Entry<Long, Map<String, UrlRecord>> entry : workingTable.entrySet()) {
                String ip = BasicUtils.intToIp(BasicUtils.getHigh4BytesFromLong(entry.getKey()));
                int dst = BasicUtils.getLow4BytesFromLong(entry.getKey());
                bufferWritter.write(ip + "." + dst + "\n");
                for (UrlRecord record : entry.getValue().values()) {
                    bufferWritter.write("\t" + record.toString() + "\n");
                }
            }
            bufferWritter.write("\n");
            bufferWritter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void cleanLastTable() {
        for (Map<String, UrlRecord> subMap : lastTable.values()) {
            subMap.clear();
        }
        lastTable.clear();
    }
}
