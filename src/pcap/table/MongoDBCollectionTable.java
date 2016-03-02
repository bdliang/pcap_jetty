package pcap.table;

import java.util.HashMap;
import java.util.Map;

import pcap.record.MongoDBCollectionRecord;
import pcap.record.MysqlServerRecord;

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

    public MysqlServerRecord getMysqlServerRecord(int ip, int port) {
        // TODO Auto-generated method stub
        return null;
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
