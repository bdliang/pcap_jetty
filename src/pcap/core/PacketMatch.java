package pcap.core;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.message.ConnectionPairMap;
import pcap.utils.BasicUtils;
import pcap.utils.PropertyUtils;

/**
 * ��ݶ˿ں��ж�Э������
 * 
 * todo Ӧ�ò�Э��
 * 
 * date : 2016.1.11
 * 
 * 
 */

public class PacketMatch {

    private static PacketMatch pm;

    private Ip4 ip = new Ip4();
    private Tcp tcp = new Tcp();

    private PacketMatch() {
        ;
    }

    public static PacketMatch getInstance() {

        if (null == pm) {
            synchronized (PacketMatch.class) {
                if (null == pm)
                    pm = new PacketMatch();
            }
        }

        return pm;
    }

    public void handlePacket(PcapPacket packet) {
        // if (packet.hasHeader(ip)) {
        // handleIp(packet);
        // }
        if (packet.hasHeader(tcp)) {
            // handleTcp4Test(packet);
            handleTcp(packet);
        }
    }
    public void handleIp(PcapPacket packet) {
        ;
    }

    public void handleTcp4Test(PcapPacket packet) {

        if (!packet.hasHeader(ip)) {
            System.err.println("It is a tcp packet, but not ip packet!");
            return;
        }

        int srcPort = tcp.source();
        int dstPort = tcp.destination();
        String ipSrc = BasicUtils.IpAddrToString(ip.source());
        String ipDst = BasicUtils.IpAddrToString(ip.destination());
        int index = PropertyUtils.hasPort(srcPort, dstPort);
        index = PropertyUtils.DeCode(index);

        if (PropertyUtils.NOT_FOUND != index) {
            String str = PropertyUtils.AppLayerName(index);
            System.out.println(str + " : " + ipSrc + "." + srcPort + " " + ipDst + "." + dstPort);
        } else {
        }
    }

    public void handleTcp(PcapPacket packet) {

        if (!packet.hasHeader(ip)) {
            System.err.println("It is a tcp packet, but not ip packet!");
            return;
        }

        int srcIp = ip.sourceToInt();
        int dstIp = ip.destinationToInt();
        int srcPort = tcp.source();
        int dstPort = tcp.destination();
        // System.err.println("\t" + srcPort + " " + +dstPort + " ");
        int index = PropertyUtils.hasPort(srcPort, dstPort);
        if (index < 0)
            return;
        ConnectionPairMap map = ConnectionPairMap.getInstance();
        map.searchTcpLink(srcIp, srcPort, dstIp, dstPort, index);
    }
}
