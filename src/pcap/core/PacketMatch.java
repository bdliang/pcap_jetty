package pcap.core;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.table.TcpTable;
import pcap.utils.BasicUtils;
import pcap.utils.PropertyUtils;

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

        int srcIp, dstIp;
        int srcPort = tcp.source();
        int dstPort = tcp.destination();

        long timeStamp = packet.getCaptureHeader().timestampInMillis();

        // 标准化，之后的src/dst都是标准化的。
        if (dstPort > srcPort) {
            // 需要颠倒
            int tmp = dstPort;
            dstPort = srcPort;
            srcPort = tmp;
            srcIp = ip.sourceToInt();
            dstIp = ip.destinationToInt();
        } else {
            srcIp = ip.destinationToInt();
            dstIp = ip.sourceToInt();
        }

        // System.err.println("\t" + srcPort + " " + +dstPort + " ");
        int index = PropertyUtils.hasPort(srcPort, dstPort);
        if (index < 0)
            return;

        TcpTable.getInstance().searchTcpRecord(srcIp, srcPort, dstIp, dstPort, index, timeStamp, tcp);
    }
}
