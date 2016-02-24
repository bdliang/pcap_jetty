package pcap.test;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.AbstractMessageHeader.MessageType;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class MyExample {

    /**
     * @param args
     * @throws IOException
     */

    public static boolean IS_CAPTURE = true;

    public static int pNum = 0;
    public static final int ETHERNET_HEADER_LEN = 6;
    public static final int IP_HEADER_LEN = 4;

    public static final int NUM_EACH_CAPTURE = 10;

    public static String localIp;

    private static int u(byte b) {
        return (b >= 0) ? b : b + 256;
    }

    // ����MAC��ַ
    public static void printMACAddr(byte[] addr) {
        if (ETHERNET_HEADER_LEN != addr.length)
            return;
        else {
            int i = 0;
            for (i = 0; i < ETHERNET_HEADER_LEN - 1; ++i) {
                System.out.print(Integer.toHexString(u(addr[i])) + "-");
            }
            System.out.print(Integer.toHexString(u(addr[i])));
            System.out.println();
        }
    }

    public static void printIpAddr(byte[] addr) {
        if (IP_HEADER_LEN != addr.length)
            return;
        else {
            int i = 0;
            for (i = 0; i < IP_HEADER_LEN - 1; ++i) {
                System.out.print(u(addr[i]) + ".");
            }
            System.out.print(u(addr[i]));
            System.out.println();
        }
    }

    public static String IpAddrToString(byte[] addr) {
        if (IP_HEADER_LEN != addr.length)
            return "";
        else {
            StringBuilder tmp = new StringBuilder();
            int i = 0;
            for (i = 0; i < IP_HEADER_LEN - 1; ++i) {
                tmp.append(u(addr[i]) + ".");
            }
            tmp.append(u(addr[i]));
            return tmp.toString();
        }
    }

    public static void main(String[] args) throws IOException {

        // PcapIf ��ӿ���
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        // ����-1 ��ʾʧ�ܣ� error��Ϣ������errbuf�С�
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.out.printf("no device available. error is %s", errbuf.toString());
            return;
        }

        // ����������豸��Ϣ
        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null ? device.getDescription() : "no description");
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        // ����MAC
        PcapIf device = alldevs.get(0);
        byte[] hdAddr = device.getHardwareAddress();
        printMACAddr(hdAddr);

        // ����ip������Ϣ
        // List<PcapAddr> addrs = device.getAddresses();
        // for (PcapAddr addr : addrs) {
        // System.out.printf("addr : %s\n", addr.toString());
        // }
        localIp = InetAddress.getLocalHost().getHostAddress().toString();// ��ñ���IP
        System.out.println(localIp);

        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription() : device.getName());
        // ��ѡ�����豸
        // int snaplen = 64 * 1024; // Capture all packets, no trucation
        int snaplen = Pcap.DEFAULT_SNAPLEN;
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 1000; // 10 seconds in millis

        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        // IS_CAPTURE = false;

        /**
         * ����һ�� PcapPacketHandler ��4����ÿ��� PcapPacketHandler ��һ��ӿڣ� ��Ҫʵ�� public
         * void nextPacket(PcapPacket packet, T user);
         */

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                Ip4 ip4 = new Ip4();
                Tcp tcp = new Tcp(); // Preallocate a Tcp header
                Http http = new Http();
                ++MyExample.pNum;
                // PcapPacket tmp = new PcapPacket(packet);
                // System.out.println(tmp.toString());
                if (packet.hasHeader(ip4)) {
                    // if (localIp.equals(IpAddrToString(ip4.source())) ||
                    // localIp.equals(IpAddrToString(ip4.destination()))) {
                    // return;
                    // }
                    System.out.printf("ip:\thdrlen = %s len = %s\n", IpAddrToString(ip4.source()), IpAddrToString(ip4.destination()));
                    if (packet.hasHeader(tcp)) {
                        System.out.printf("\ttcp:\ttype = %d src = %d dst = %d len = %d seq = %d ack = %d\n", ip4.type(), tcp.source(),
                                tcp.destination(), tcp.getLength(), tcp.seq(), tcp.ack());
                        if (packet.hasHeader(http)) {
                            String mesType = null;
                            if (MessageType.REQUEST == http.getMessageType()) {
                                mesType = "request";
                            } else if (MessageType.RESPONSE == http.getMessageType()) {
                                mesType = "response";
                            }
                            System.out.printf("\t\thttp = %s mesType = %s\n", http.contentTypeEnum().name(), mesType);
                        }

                    } else {
                        System.out.println("\tnextType = " + ip4.type());
                    }
                    System.out.println();
                } else {
                    // Date date = new
                    // Date(packet.getCaptureHeader().timestampInMillis());
                    // System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                    // date, packet.getCaptureHeader().caplen(), // Length
                    // // actually
                    // // captured
                    // packet.getCaptureHeader().wirelen(), // Original
                    // // length
                    // user // User supplied object
                    // );
                }
            }
        };

        int loopNum = 10;
        while (IS_CAPTURE && loopNum > 0 && Pcap.OK == pcap.loop(NUM_EACH_CAPTURE, jpacketHandler, "jNetPcap rocks!")) {
            --loopNum;
        }

        pcap.close();
        System.out.printf("\njnetpcap closed. pNum = %d\n", MyExample.pNum);

        // JBufferHandler<String> handler = new JBufferHandler<String>() {
        //
        // private final PcapPacket packet = new PcapPacket(JMemory.POINTER);
        //
        // public void nextPacket(PcapHeader header, JBuffer buffer, String msg)
        // {
        // packet.peer(buffer); // Peer the data to our packet
        // packet.getCaptureHeader().peerTo(header, 0);
        //
        // packet.scan(Ethernet.ID); // Assuming that first header in packet is
        // ethernet
        // Ip4 ip = new Ip4();
        // Tcp tcp = new Tcp();
        // if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
        // System.out.println(ip.toString());
        // System.out.println(tcp.toString());
        // }
        // }
        // };

    }
}

// PcapBpfProgram program = new PcapBpfProgram();
// String expression = "host 192.168.1.1";
// int optimize = 0; // 0 = false
// int netmask = 0xFFFFFF00; // 255.255.255.0
//
// if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
// System.err.println(pcap.getErr());
// return;
// }
//
// if (pcap.setFilter(program) != Pcap.OK) {
// System.err.println(pcap.getErr());
// return;
// }
