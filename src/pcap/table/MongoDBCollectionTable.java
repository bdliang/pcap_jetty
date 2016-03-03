package pcap.table;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import pcap.record.MongoDBCollectionRecord;
import pcap.record.MongoDBCollectionRecord.MongoDBItems;
import pcap.utils.BasicUtils;

public class MongoDBCollectionTable implements TableAction {
    /**
     * 以MongoDB的collection为单位来记录MongoDB记录
     * 
     * 外层以ip,port拼成的Long作为外层主键, 以collection名字为内层主键
     */

    private static MongoDBCollectionTable single;

    private Map<Long, Map<String, MongoDBCollectionRecord>> mongodbMap;

    private MongoDBCollectionTable() {
        mongodbMap = new HashMap<Long, Map<String, MongoDBCollectionRecord>>();
    }

    /* 单例 */
    public static MongoDBCollectionTable getInstance() {
        if (null == single) {
            synchronized (MongoDBCollectionTable.class) {
                if (null == single) {
                    single = new MongoDBCollectionTable();
                }
            }
        }
        return single;
    }

    public MongoDBCollectionRecord getMongoDBCollectionRecord(int ip, int port, String dbCollection) {

        MongoDBCollectionRecord record = null;
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(dbCollection))
            return null;

        long key = BasicUtils.ping2Int(ip, port);
        Map<String, MongoDBCollectionRecord> subMap = mongodbMap.get(key);
        if (null == subMap) {
            subMap = new HashMap<String, MongoDBCollectionRecord>();
            record = new MongoDBCollectionRecord(ip, port, dbCollection);
            subMap.put(dbCollection, record);
            mongodbMap.put(key, subMap);
        } else {
            record = subMap.get(dbCollection);
            if (null == record) {
                record = new MongoDBCollectionRecord(ip, port, dbCollection);
                subMap.put(dbCollection, record);
            }
        }
        return record;
    }

    /* 整体查找 */
    /**
     * 获得所有item属性的个数
     */
    public int getCount(MongoDBItems item) {
        if (null == item)
            return 0;
        int cnt = 0;
        for (Map<String, MongoDBCollectionRecord> subMap : mongodbMap.values()) {
            for (MongoDBCollectionRecord record : subMap.values()) {
                cnt += record.getItemCount(item);
            }
        }
        return cnt;
    }

    /**
     * 返回所有url的平均响应时间
     */
    public double getAvgTime() {
        long time = 0;
        long cnt = 0;
        for (Map<String, MongoDBCollectionRecord> subMap : mongodbMap.values()) {
            for (MongoDBCollectionRecord record : subMap.values()) {
                time += record.getTotalTime();
                cnt += record.getTotalCount();
            }
        }
        return (cnt > 0) ? (time * 1.0) / cnt : 0.0;
    }

    /* 根据ip查找 */
    /**
     * 获得所有item属性的个数
     * 
     * @param ip
     *            ip地址
     */
    public int getCountByIp(MongoDBItems item, int ip) {
        if (null == item)
            return 0;
        int cnt = 0;
        for (Long ipPort : mongodbMap.keySet()) {
            if (ip != BasicUtils.getHigh4BytesFromLong(ipPort))
                continue;
            Map<String, MongoDBCollectionRecord> subMap = mongodbMap.get(ipPort);
            for (MongoDBCollectionRecord record : subMap.values()) {
                cnt += record.getItemCount(item);
            }
        }
        return cnt;
    }

    /**
     * 返回所有url的平均响应时间
     * 
     * @param ip
     *            ip地址
     */
    public double getAvgTimeByIp(int ip) {
        long time = 0;
        long cnt = 0;
        for (Long ipPort : mongodbMap.keySet()) {
            if (ip != BasicUtils.getHigh4BytesFromLong(ipPort))
                continue;
            Map<String, MongoDBCollectionRecord> subMap = mongodbMap.get(ipPort);
            for (MongoDBCollectionRecord record : subMap.values()) {
                time += record.getTotalTime();
                cnt += record.getTotalCount();
            }
        }

        return (cnt > 0) ? (time * 1.0) / cnt : 0.0;
    }

    /* 根据ip, port查找 */
    /**
     * 获得所有item属性的个数
     * 
     * @param ip
     *            ip地址
     * @param port
     *            port值
     * 
     */
    public int getCountByIpPort(MongoDBItems item, int ip, int port) {
        if (!BasicUtils.isPortValid(port) || null == item)
            return 0;
        int cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, MongoDBCollectionRecord> subMap = mongodbMap.get(key);
        if (null == subMap)
            return 0;
        for (MongoDBCollectionRecord record : subMap.values()) {
            cnt += record.getItemCount(item);
        }
        return cnt;
    }

    /**
     * 返回所有url的平均响应时间
     * 
     * @param ip
     *            ip地址
     * 
     * @param port
     *            port值
     */
    public double getAvgTimeByIpPort(int ip, int port) {
        if (!BasicUtils.isPortValid(port))
            return 0.0;
        long time = 0;
        long cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, MongoDBCollectionRecord> subMap = mongodbMap.get(key);
        if (null == subMap)
            return 0;
        for (MongoDBCollectionRecord record : subMap.values()) {
            time += record.getTotalTime();
            cnt += record.getTotalCount();
        }
        return (cnt > 0) ? (time * 1.0) / cnt : 0.0;
    }

    /* 根据ip, port, collection查找 */
    /**
     * @param ip
     *            ip地址
     * 
     * @param port
     *            port值
     * @param dbCollection
     *            database.collection
     */
    public int getCountByIpPortDBC(int ip, int port, String dbCollection, MongoDBItems item) {
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(dbCollection) || null == item)
            return 0;
        int cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, MongoDBCollectionRecord> subMap = null;
        MongoDBCollectionRecord record = null;
        if (null == (subMap = mongodbMap.get(key)) || null == (record = subMap.get(dbCollection)))
            return 0;
        cnt = record.getItemCount(item);
        return cnt;
    }

    /**
     * @param ip
     *            ip地址
     * 
     * @param port
     *            port值
     * @param dbCollection
     *            database.collection
     */
    public double getAvgTimeByIpPortDBC(int ip, int port, String dbCollection) {
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(dbCollection))
            return 0.0;
        long time = 0;
        long cnt = 0;
        long key = BasicUtils.ping2Int(ip, port);
        Map<String, MongoDBCollectionRecord> subMap = null;
        MongoDBCollectionRecord record = null;
        if (null == (subMap = mongodbMap.get(key)) || null == (record = subMap.get(dbCollection)))
            return 0.0;
        time = record.getTotalTime();
        cnt = record.getTotalCount();
        return (cnt > 0) ? (time * 1.0) / cnt : 0.0;
    }

    @Override
    public void clean() {
        System.out.println("MongoDBCollectionTable clean");
        for (Map<String, MongoDBCollectionRecord> subMap : mongodbMap.values()) {
            subMap.clear();
        }
        mongodbMap.clear();
    }

    @Override
    public void dumpToFile() {
        File file = new File(TableAction.filePath);
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fileWritter = new FileWriter(file.getName(), true);
            BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
            bufferWritter.write("#### MongoDB Record ####\n");
            // Map<Long, Map<String, UrlRecord>> map
            for (Map.Entry<Long, Map<String, MongoDBCollectionRecord>> entry : mongodbMap.entrySet()) {
                String ip = BasicUtils.intToIp(BasicUtils.getHigh4BytesFromLong(entry.getKey()));
                int dst = BasicUtils.getLow4BytesFromLong(entry.getKey());
                bufferWritter.write(ip + "." + dst + "\n");
                for (MongoDBCollectionRecord record : entry.getValue().values()) {
                    bufferWritter.write("\t" + record.toString() + "\n");
                }
            }
            bufferWritter.write("\n");
            bufferWritter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
