package pcap.test;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * version 0.1 ��ץȡ ipv4, tcp
 * 
 * todo Ӧ�ò�Э��
 * 
 * date : 2016.1.7
 * 
 * 
 * */
public class CaptureDemo1 {

    public static boolean IS_CAPTURE = true;

    public static final int NUM_EACH_CAPTURE = 10;

    public static String localIp;

    public static void main(String[] args) throws IOException {

        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.out.printf("no device available. error is %s", errbuf.toString());
            return;
        }

        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null ? device.getDescription() : "no description");
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        localIp = InetAddress.getLocalHost().getHostAddress().toString();// ��ñ���IP
        System.out.println(localIp);

        PcapIf device = alldevs.get(0);
        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription() : device.getName());
        // ��ѡ�����豸
        int snaplen = Pcap.DEFAULT_SNAPLEN;
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 1000; // 10 seconds in millis

        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                Ip4 ip4 = new Ip4();
                Tcp tcp = new Tcp(); // Preallocate a Tcp header
                Http http = new Http();
                ++MyExample.pNum;
                if (packet.hasHeader(ip4)) {
                    // if
                    // (localIp.equals(JnetPcapMyConstant.IpAddrToString(ip4.source()))
                    // ||
                    // localIp.equals(JnetPcapMyConstant.IpAddrToString(ip4.destination())))
                    // {
                    // return;
                    // }
                    // System.out.printf("ip:\thdrlen = %s len = %s\n",
                    // JnetPcapMyConstant.IpAddrToString(ip4.source()),
                    // JnetPcapMyConstant.IpAddrToString(ip4.destination()));
                    if (packet.hasHeader(tcp)) {
                        // System.out.printf("\ttcp:\ttype = %d src = %d dst = %d len = %d seq = %d ack = %d\n",
                        // ip4.type(), tcp.source(),
                        // tcp.destination(), tcp.getLength(), tcp.seq(),
                        // tcp.ack());
                        if (packet.hasHeader(http)) {
                            // String mesType = null;
                            // if (MessageType.REQUEST == http.getMessageType())
                            // {
                            // mesType = "request";
                            // } else if (MessageType.RESPONSE ==
                            // http.getMessageType()) {
                            // mesType = "response";
                            // }
                            // JField[] fields = http.getFields();
                            // System.out.printf("\t\thttp = %s \nmesType = %s\n",
                            // http.toString(), mesType);

                            String s1 = http.fieldValue(Http.Request.Content_Type);
                            String s2 = http.fieldValue(Http.Request.Content_Type);
                            System.out.printf("s1 = %s\ns2 = %s\n", s1, s2);
                        }

                    } else {
                        // System.out.println("\tnextType = " + ip4.type());
                    }
                    System.out.println();
                } else {
                }
            }
        };

        int loopNum = 20;
        while (IS_CAPTURE && loopNum > 0 && Pcap.OK == pcap.loop(NUM_EACH_CAPTURE, jpacketHandler, "jNetPcap rocks!")) {
            --loopNum;
        }

        pcap.close();
        System.out.printf("\njnetpcap closed. pNum = %d\n", MyExample.pNum);

    }
}
