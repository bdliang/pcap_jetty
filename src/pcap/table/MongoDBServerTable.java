package pcap.table;

import java.util.HashMap;
import java.util.Map;

import pcap.record.MysqlServerRecord;

public class MongoDBServerTable implements TableAction {

    private static MongoDBServerTable single;

    private Map<Long, MongoDBServerTable> mysqlServerMap;

    private MongoDBServerTable() {
        mysqlServerMap = new HashMap<Long, MongoDBServerTable>();
    }

    /* 单例 */
    public static MongoDBServerTable getInstance() {
        if (null == single) {
            synchronized (MongoDBServerTable.class) {
                if (null == single) {
                    single = new MongoDBServerTable();
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

    @Override
    public void clean() {
        // TODO Auto-generated method stub

    }

    @Override
    public void dumpToFile() {
        // TODO Auto-generated method stub

    }

}
