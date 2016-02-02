package pcap.table;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.decode.HttpDecode;
import pcap.record.TcpRecord;
import pcap.utils.BasicUtils;
import pcap.utils.PropertyUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class TcpTable implements TableAction {

    private static TcpTable single;

    private Map<Long, Map<Integer, TcpRecord>> ipMapPort;

    private TcpTable() {
        ipMapPort = new ConcurrentHashMap<Long, Map<Integer, TcpRecord>>();
    }

    public int mapNum() {
        return ipMapPort.size();
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

        decodePacket(tcp, record, timeStamp);
    }

    /**
     * 传入的参数需要标准化。 根据解析的tcp信息，加入到TcpTable中。
     * */
    public void searchTcpRecord(int ipSrc, int portSrc, int ipDst, int portDst, int index, long timeStamp, Tcp tcp) {
        if (null == tcp || timeStamp <= 0)
            return;

        long ipPair;
        int portPair;
        ipPair = BasicUtils.ping2Int(ipSrc, ipDst);
        portPair = BasicUtils.ping2port(portSrc, portDst);

        if (ipMapPort.containsKey(ipPair)) {
            searchPortMapLink(ipMapPort.get(ipPair), portPair, ipSrc, portSrc, ipDst, portDst, index, timeStamp, tcp);
        } else {
            Map<Integer, TcpRecord> tmp = new ConcurrentHashMap<Integer, TcpRecord>();
            ipMapPort.put(ipPair, tmp);
            searchPortMapLink(tmp, portPair, ipSrc, portSrc, ipDst, portDst, index, timeStamp, tcp);
        }
    }

    /**
     * 从记录的tcp中选择， 源或目的是指定ip的，并且端口有http的tcp连接。
     * 
     * @return 返回符合条件的列表
     * */
    public List<TcpRecord> selectIpWithHttp(int ip1) {
        List<TcpRecord> result = new ArrayList<TcpRecord>();
        Set<Long> set = ipMapPort.keySet();
        for (Long l : set) {
            int high4 = BasicUtils.getHigh4BytesFromLong(l);
            int low4 = BasicUtils.getLow4BytesFromLong(l);
            if ((ip1 == high4) || (ip1 == low4)) {
                getHttpTcp(l, result);
            }
        }
        return result;
    }

    /**
     * 在指定ipPair的tcp连接中，找出端口是http监控的tcp连接，并加入到结果列表中。
     * 
     * 结果列表如果为空，直接返回
     * */
    public void getHttpTcp(long ipPair, List<TcpRecord> result) {
        if (null == result)
            return;
        Map<Integer, TcpRecord> portMap = ipMapPort.get(ipPair);
        if (null != portMap) {
            for (Integer portPair : portMap.keySet()) {
                int high2 = BasicUtils.getHigh2BytesFromLong(portPair);
                int low2 = BasicUtils.getLow2BytesFromLong(portPair);
                List<Integer> ports = PropertyUtils.getAppPort("http".toLowerCase());
                if (ports.contains(high2) || ports.contains(low2)) {
                    result.add(portMap.get(portPair));
                }
            }
        }
    }

    @Override
    public void clean() {
        System.out.println("TcpTable clean");
        for (Map<Integer, TcpRecord> map : ipMapPort.values()) {
            map.clear();
        }
        ipMapPort.clear();
    }

    public void decodePacket(Tcp tcp, TcpRecord record, long timeStamp) {
        if (null == tcp || null == record)
            return;
        String type = record.getType().toLowerCase();
        if (0 == type.length()) {
            return;
        } else if (type.equals("http")) {
            HttpDecode.decode(tcp.getPayload(), record, timeStamp);
        } else if (type.equals("mysql")) {
        } else if (type.equals("pgsql")) {
        } else if (type.equals("redis")) {
        } else if (type.equals("mongodb")) {
        } else if (type.equals("ldap")) {
        }
    }
}
