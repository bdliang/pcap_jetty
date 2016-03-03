package pcap.table;

import java.util.HashMap;
import java.util.Map;

import pcap.record.MongoDBCollectionRecord;
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

    public MongoDBCollectionRecord getMongoDBCollectionRecord(int ip, int port,
            String name) {

        MongoDBCollectionRecord record = null;
        if (!BasicUtils.isPortValid(port) || BasicUtils.isStringBlank(name))
            return null;

        long key = BasicUtils.ping2Int(ip, port);
        Map<String, MongoDBCollectionRecord> subMap = mongodbMap.get(key);
        if (null == subMap) {
            subMap = new HashMap<String, MongoDBCollectionRecord>();
            record = new MongoDBCollectionRecord(ip, port, name);
            subMap.put(name, record);
            mongodbMap.put(key, subMap);
        } else {
            record = subMap.get(name);
            if (null == record) {
                record = new MongoDBCollectionRecord(ip, port, name);
                subMap.put(name, record);
            }
        }
        return record;
    }

    /* 整体查找 */
    /* 根据ip查找 */
    /* 根据ip, port查找 */
    /* 根据ip, port, collection查找 */

    @Override
    public void clean() {
        // TODO Auto-generated method stub

    }

    @Override
    public void dumpToFile() {
        // TODO Auto-generated method stub

    }

}
