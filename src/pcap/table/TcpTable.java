package pcap.table;

import net.sf.json.JSONArray;

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

public class TcpTable implements TableAction {

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

    private Map<Long, Map<Integer, TcpRecord>> ipMapPort;

    private TcpTable() {
        ipMapPort = new ConcurrentHashMap<Long, Map<Integer, TcpRecord>>();
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

    public int mapNum() {
        return ipMapPort.size();
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

        long ipPair;
        int portPair;
        ipPair = BasicUtils.ping2Int(ipSrc, ipDst);
        portPair = BasicUtils.ping2port(portSrc, portDst);

        Map<Integer, TcpRecord> subMap = ipMapPort.get(ipPair);
        if (null != subMap) {
            searchPortMapLink(subMap, portPair, ipSrc, portSrc, ipDst, portDst, index, timeStamp, tcp);
        } else {
            subMap = new ConcurrentHashMap<Integer, TcpRecord>();
            ipMapPort.put(ipPair, subMap);
            searchPortMapLink(subMap, portPair, ipSrc, portSrc, ipDst, portDst, index, timeStamp, tcp);
        }
    }

    /**
     * 从记录的tcp中选择， 源或目的是指定ip的，并且端口有http的tcp连接。
     * 
     * @return 返回符合条件的列表。当没有符合条件的记录时，返回空List，不返回NULL。
     * */
    private List<TcpRecord> selectIpWithHttp0(int ip1) {
        List<TcpRecord> result = new ArrayList<TcpRecord>();
        for (Long ipPair : ipMapPort.keySet()) {
            int high4 = BasicUtils.getHigh4BytesFromLong(ipPair);
            int low4 = BasicUtils.getLow4BytesFromLong(ipPair);
            if ((ip1 == high4) || (ip1 == low4)) {
                Map<Integer, TcpRecord> portMap = ipMapPort.get(ipPair);
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

    /**
     * 从记录的tcp中选择， 源或目的是指定ip的，并且端口有http的tcp连接。
     * 
     * @return 返回对应List的JSON字符串
     * */
    public String selectIpWithHttp(String ipString) {
        List<TcpRecord> result = null;
        if (!BasicUtils.isStringIp(ipString)) {
            result = new ArrayList<TcpRecord>(0);
        } else {
            result = selectIpWithHttp0(BasicUtils.ipStringToInt(ipString));
        }
        return JSONArray.fromObject(result, TcpRecord.config).toString();
    }

    @Override
    public void clean() {
        System.out.println("TcpTable clean");
        for (Map<Integer, TcpRecord> map : ipMapPort.values()) {
            map.clear();
        }
        ipMapPort.clear();
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
            bufferWritter.write(new Date(System.currentTimeMillis()).toString() + "\n");
            bufferWritter.write("#### Tcp Record ####\n");
            for (Map.Entry<Long, Map<Integer, TcpRecord>> entry : ipMapPort.entrySet()) {
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
}
