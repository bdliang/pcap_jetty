package pcap.table;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.core.PortMonitorMap;
import pcap.decode.Decode;
import pcap.record.TcpRecord;
import pcap.utils.BasicUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TcpTable extends Table<Long, Map<Integer, TcpRecord>> implements TableAction {

    /**
     * 用于记录TcpRecord的表, 两层map。
     * 
     * 将TcpRecord中的ipSrc, ipDst拼成一个long型(ipSrc高4位, ipDst低4位)作为外层map的key。
     * 将TcpRecord中的portSrc, portDst拼成一个int型(portSrc高2位, portDst低2位)作为内层map的key。
     * 
     * 之所以要这样做，是因为给 应用拓扑 服务。用于查与某个ip有关联的应用的查找，参见 selectIpWithHttp()。
     * 
     * */

    private static TcpTable single;

    private TcpTable() {
        currentTable = new ConcurrentHashMap<Long, Map<Integer, TcpRecord>>();
        lastTable = new ConcurrentHashMap<Long, Map<Integer, TcpRecord>>();
        workingTable = currentTable;
    }

    public static TcpTable getInstance() {
        if (null == single) {
            synchronized (TcpTable.class) {
                if (null == single) {
                    single = new TcpTable();
                }
            }
        }
        return single;
    }

    public int mapNum(boolean current) {
        setWorkingTable(current);
        return workingTable.size();
    }

    public void searchPortMapLink(Map<Integer, TcpRecord> map, int portPair, int ipSrc, int portSrc, int ipDst, int portDst, int index,
            long timeStamp, Tcp tcp) {
        if (null == map)
            return;
        TcpRecord record = map.get(portPair);
        if (null != record) {
            // tmp = map.get(portPair);
        } else {
            record = new TcpRecord(ipSrc, portSrc, ipDst, portDst, index);
            map.put(portPair, record);
        }
        Decode.decodePacket(tcp, record, timeStamp);
    }

    /**
     * ###### 传入的参数需要标准化 #######。
     * 
     * 根据解析的tcp信息，加入到TcpTable中。
     * */
    public void searchTcpRecord(int ipSrc, int portSrc, int ipDst, int portDst, int index, long timeStamp, Tcp tcp) {
        if (null == tcp || timeStamp <= 0)
            return;

        setWorkingTable(true);
        long ipPair;
        int portPair;
        ipPair = BasicUtils.ping2Int(ipSrc, ipDst);
        portPair = BasicUtils.ping2port(portSrc, portDst);

        Map<Integer, TcpRecord> subMap = workingTable.get(ipPair);
        if (null != subMap) {
            searchPortMapLink(subMap, portPair, ipSrc, portSrc, ipDst, portDst, index, timeStamp, tcp);
        } else {
            subMap = new ConcurrentHashMap<Integer, TcpRecord>();
            workingTable.put(ipPair, subMap);
            searchPortMapLink(subMap, portPair, ipSrc, portSrc, ipDst, portDst, index, timeStamp, tcp);
        }
    }

    /**
     * 从记录的tcp中选择， 源或目的是指定ip的，并且端口有http的tcp连接。
     * 
     * @param 在双表设计的条件下
     *            ， current表示从哪个表查找数据
     * 
     * @return 返回符合条件的列表
     * */
    public List<TcpRecord> selectIpWithHttp(int ip1, boolean current) {
        setWorkingTable(current);
        List<TcpRecord> result = new ArrayList<TcpRecord>();
        for (Long ipPair : workingTable.keySet()) {
            int high4 = BasicUtils.getHigh4BytesFromLong(ipPair);
            int low4 = BasicUtils.getLow4BytesFromLong(ipPair);
            if ((ip1 == high4) || (ip1 == low4)) {
                Map<Integer, TcpRecord> portMap = workingTable.get(ipPair);
                for (Integer portPair : portMap.keySet()) {
                    int high2 = BasicUtils.getHigh2BytesFromLong(portPair);
                    int low2 = BasicUtils.getLow2BytesFromLong(portPair);
                    List<Integer> ports = PortMonitorMap.getInstance().getAppPort("http".toLowerCase());
                    if (null == ports)
                        continue;
                    if (ports.contains(high2) || ports.contains(low2)) {
                        result.add(portMap.get(portPair));
                    }
                }
            }
        }
        return result;
    }

    @Override
    public void clean() {
        System.out.println("TcpTable clean");
        for (Map<Integer, TcpRecord> map : lastTable.values()) {
            map.clear();
        }
        lastTable.clear();

        for (Map<Integer, TcpRecord> map : currentTable.values()) {
            map.clear();
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
            bufferWritter.write(new Date(System.currentTimeMillis()).toString() + "\n");
            bufferWritter.write("#### Tcp Record ####\n");
            for (Map.Entry<Long, Map<Integer, TcpRecord>> entry : workingTable.entrySet()) {
                String src = BasicUtils.intToIp(BasicUtils.getHigh4BytesFromLong(entry.getKey()));
                String dst = BasicUtils.intToIp(BasicUtils.getLow4BytesFromLong(entry.getKey()));
                bufferWritter.write(src + " " + dst + "\n");
                for (TcpRecord record : entry.getValue().values()) {
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
        for (Map<Integer, TcpRecord> map : lastTable.values()) {
            map.clear();
        }
        lastTable.clear();
    }

}
