package pcap.message;

import pcap.utils.BasicUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 单例模式
 * 
 * */
public class ConnectionPairMap {

    private static ConnectionPairMap single;

    private Map<Long, Map<Integer, TcpLink>> ipMapPort;

    private ConnectionPairMap() {
        ipMapPort = new ConcurrentHashMap<Long, Map<Integer, TcpLink>>();
    }

    public int mapNum() {
        return ipMapPort.size();
    }

    public static ConnectionPairMap getInstance() {
        if (null == single) {
            synchronized (ConnectionPairMap.class) {
                if (null == single) {
                    single = new ConnectionPairMap();
                }
            }
        }
        return single;
    }

    public void searchportMapLink(Map<Integer, TcpLink> map, int portPair, int ipSrc, int portSrc, int ipDst, int portDst, int index) {
        if (null == map)
            return;
        TcpLink tmp = null;
        if (map.containsKey(portPair)) {
            tmp = map.get(portPair);
            tmp.morePacket(portSrc > portDst);
        } else {
            tmp = new TcpLink(ipSrc, portSrc, ipDst, portDst);
            tmp.startRecord();
            tmp.morePacket(portSrc > portDst);
            tmp.decodeType(index);
            map.put(portPair, tmp);
        }
    }

    public void searchTcpLink(int ipSrc, int portSrc, int ipDst, int portDst, int index) {

        long ipPair;
        int portPair;
        if (portSrc < portDst) {
            ipPair = BasicUtils.ping2Int(ipDst, ipSrc);
            portPair = BasicUtils.ping2port(portDst, portSrc);
        } else {
            ipPair = BasicUtils.ping2Int(ipSrc, ipDst);
            portPair = BasicUtils.ping2port(portSrc, portDst);
        }

        if (ipMapPort.containsKey(ipPair)) {
            searchportMapLink(ipMapPort.get(ipPair), portPair, ipSrc, portSrc, ipDst, portDst, index);
        } else {
            Map<Integer, TcpLink> tmp = new ConcurrentHashMap<Integer, TcpLink>();
            ipMapPort.put(ipPair, tmp);
            searchportMapLink(tmp, portPair, ipSrc, portSrc, ipDst, portDst, index);
        }
    }

    /**
     * 将connectionPairMap 中维持的tcp 连接 dump到 TcpLinksForRequest 中
     * 
     * TcpLink 对象中， indexInBuffer 是 该tcp连接 在 TcpLinksForRequest的list中的 index.
     * 
     * dump后， connectionPairMap中 所有tcp都会调用 resetRecord()方法。
     * 
     * 通过，isClean 来决定是否清空 connectionPairMap。
     * 
     * */
    public void tranferValuesToBuffer(List<TcpLink> l, boolean isClean) {

        Long time = System.currentTimeMillis();
        for (Map<Integer, TcpLink> map : ipMapPort.values()) {
            for (TcpLink tcp : map.values()) {
                tcp.endTimeSet(time);
                if (tcp.isIndexValid()) {
                    // 已经在 TcpLinksForRequest 中有一份了
                    TcpLink tmp = l.get(tcp.indexInBufferGet());
                    tmp.mergeTcpRecord(tcp);
                } else {
                    // 添加到 TcpLinksForRequest
                    tcp.indexInBufferSet(l.size());
                    l.add(new TcpLink(tcp));
                }
                tcp.resetRecord();
            }
            if (isClean)
                map.clear();
        }
        if (isClean)
            ipMapPort.clear();
    }

    public static final int ALLONE = 0xffffffff;
    // / 从记录的tcp中选择， 一方有ip1或ip2， 或 ip1和ip2之间tcp的一条记录
    public List<TcpLink> selectFirst(int ip1, int ip2) {
        List<TcpLink> result = new ArrayList<TcpLink>();
        TcpLink tmp = null;
        Set<Long> set = ipMapPort.keySet();
        for (Long l : set) {
            int high4 = BasicUtils.getHigh4BytesFromLong(l);
            int low4 = BasicUtils.getLow4BytesFromLong(l);
            if ((ip1 == high4) || (ip1 == low4) || (ip2 == high4) || (ip2 == low4)) {
                tmp = getOneTcp(l);
                if (null != tmp)
                    result.add(tmp);
            }
        }
        return result;
    }

    // 扩展selectFirst， 从两个参数扩展成 int[]
    public List<TcpLink> selectFirst(int[] ips) {
        List<TcpLink> result = new ArrayList<TcpLink>();
        if (0 == ips.length) {
            return result;
        }
        TcpLink tmp = null;
        Set<Long> set = ipMapPort.keySet();
        for (Long l : set) {
            int high4 = BasicUtils.getHigh4BytesFromLong(l);
            int low4 = BasicUtils.getLow4BytesFromLong(l);
            for (int ip : ips) {
                if (high4 == ip || low4 == ip) {
                    tmp = getOneTcp(l);
                    if (null != tmp)
                        result.add(tmp);
                }
            }
        }
        return result;
    }

    public TcpLink getOneTcp(long ipPair) {
        Map<Integer, TcpLink> portMap = null;
        if (ipMapPort.containsKey(ipPair)) {
            portMap = ipMapPort.get(ipPair);
            Object[] objs = portMap.values().toArray();
            if (objs.length > 0)
                return (TcpLink) (objs[0]);
        }
        return null;
    }

    public void clean() {

        System.out.println("ConnectionPairMap clean");
        for (Map<Integer, TcpLink> map : ipMapPort.values()) {
            map.clear();
        }
        ipMapPort.clear();
    }
}
