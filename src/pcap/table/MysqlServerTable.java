package pcap.table;

import pcap.record.MysqlServerRecord;
import pcap.record.MysqlServerRecord.MysqlItems;
import pcap.utils.BasicUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;

public class MysqlServerTable extends Table<Long, MysqlServerRecord> implements TableAction {

    /**
     * 用来记录mysql的表
     * 
     * ip, port作为主键， MysqlServerRecord 作为值。其中， ip和port拼成long型作为k1,
     * map->MysqlServerRecord
     * 
     * 提供整体的和某个ip或某对ip/port或某个mysql服务器的相关统计和响应时间
     * */

    private static MysqlServerTable single;

    private MysqlServerTable() {
        currentTable = new HashMap<Long, MysqlServerRecord>();
        lastTable = new HashMap<Long, MysqlServerRecord>();
        workingTable = currentTable;
    }

    /* 单例 */
    public static MysqlServerTable getInstance() {
        if (null == single) {
            synchronized (UrlTable.class) {
                if (null == single) {
                    single = new MysqlServerTable();
                }
            }
        }
        return single;
    }

    /**
     * 在MysqlServerTable中， 查找 ip, port对应的记录
     * 
     * @return 存在记录则返回该记录；否则新建一个记录加入到表中并返回该记录。如果有不符合条件的，则返回null
     * */
    public MysqlServerRecord getMysqlServerRecord(int ip, int port) {
        MysqlServerRecord record = null;
        if (!BasicUtils.isPortValid(port))
            return null;
        setWorkingTable(true);
        long key = BasicUtils.ping2Int(ip, port);
        record = workingTable.get(key);

        if (null == record) {
            record = new MysqlServerRecord(ip, port);
            workingTable.put(key, record);
        }
        return record;
    }

    /* 整体查找 */
    /**
     * 获得所有item属性的个数
     * */
    public int getCount(MysqlItems item, boolean current) {
        if (null == item || MysqlItems.OTHER == item)
            return 0;
        setWorkingTable(current);
        int cnt = 0;
        for (MysqlServerRecord record : workingTable.values()) {
            cnt += record.getItemCount(item);
        }
        return cnt;
    }

    /**
     * 返回所有mysql增删改查请求的平均响应时间
     * */
    public double getAvgTime(boolean current) {
        setWorkingTable(current);
        long time = 0;
        long cnt = 0;
        for (MysqlServerRecord record : workingTable.values()) {
            time += record.getTotalTime();
            cnt += record.getTotalCount();
        }
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    /* 根据ip查找 */
    public int getCountByIp(MysqlItems item, int ip, boolean current) {
        if (null == item || MysqlItems.OTHER == item)
            return 0;
        setWorkingTable(current);
        int cnt = 0;
        for (Long ipPort : workingTable.keySet()) {
            if (ip != BasicUtils.getHigh4BytesFromLong(ipPort))
                continue;
            MysqlServerRecord record = workingTable.get(ipPort);
            cnt += record.getItemCount(item);
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
            MysqlServerRecord record = workingTable.get(ipPort);
            time += record.getTotalTime();
            cnt += record.getTotalCount();
        }
        if (cnt > 0)
            return (time * 1.0) / cnt;
        return 0.0;
    }

    @Override
    public void clean() {
        System.out.println("MysqlServerTable clean");
        lastTable.clear();
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
            bufferWritter.write("#### Mysql Server Record ####\n");
            for (Long ipPort : workingTable.keySet()) {
                String ip = BasicUtils.intToIp(BasicUtils.getHigh4BytesFromLong(ipPort));
                int port = BasicUtils.getLow4BytesFromLong(ipPort);
                bufferWritter.write(ip + "." + port + "\n");
                MysqlServerRecord record = workingTable.get(ipPort);
                bufferWritter.write("\t" + record.toString() + "\n");
            }
            bufferWritter.write("\n");
            bufferWritter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void cleanLastTable() {
        lastTable.clear();
    }

}
