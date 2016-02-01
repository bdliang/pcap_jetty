package pcap.core;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;

import pcap.handler.MyPcapHandler;
import pcap.utils.BasicUtils;
import pcap.utils.PropertyUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class CaptureCore implements Runnable {

    public static String localIp;

    public static int capNum;

    public static boolean IS_CAPTURE = true; // for test

    public static final int NUM_EACH_CAPTURE = 10;

    public static List<PcapIf> allDevs = null;

    static {
        PropertyUtils.defaultConfiguration();
    }

    public static void EnableCapture() {
        IS_CAPTURE = true;
    }

    public static void DisableCapture() {
        IS_CAPTURE = false;
    }

    public static List<PcapIf> getDevices() {
        allDevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        try {
            localIp = InetAddress.getLocalHost().getHostAddress().toString();// ��ñ���IP
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        System.out.println("host : " + localIp);

        int r = Pcap.findAllDevs(allDevs, errbuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.out.printf("no device available. error is %s", errbuf.toString());
            return null;
        }
        return allDevs;
    }

    public static void printDevices() {
        if (null == allDevs)
            allDevs = getDevices();
        int i = 0;
        for (PcapIf device : allDevs) {
            String description = (device.getDescription() != null ? device.getDescription() : "no description");
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }
    }

    public static void startSniff(int seq, int loopNum, int eachCatch, boolean allTime) {
        if (null == allDevs)
            allDevs = getDevices();
        StringBuilder errbuf = new StringBuilder();
        String deviceName = null;
        if (-1 == seq) {
            deviceName = "any";
            System.out.printf("\nChoosing ALL DEVICES on your behalf:\n");
        } else {
            PcapIf device = allDevs.get(seq);
            deviceName = device.getName();
            System.out.printf("\nChoosing '%s' on your behalf:\n",
                    (device.getDescription() != null) ? device.getDescription() : device.getName());

        }

        int snaplen = Pcap.DEFAULT_SNAPLEN;// ����65536
        int flags = Pcap.MODE_PROMISCUOUS;// ����ģʽ
        int timeout = BasicUtils.DEFAULT_TIMEOUT;
        // StringBuilder errsb = null;
        Pcap pcap = Pcap.openLive(deviceName, snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        PcapBpfProgram program = new PcapBpfProgram();
        String expression = "tcp";
        int optimize = 0; // 0 = false
        int netmask = 0; // 255.255.255.0

        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return;
        }

        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return;
        }

        MyPcapHandler<Object> myhandler = new MyPcapHandler<Object>();

        loopNum = (loopNum > 0) ? loopNum : 20;
        eachCatch = (eachCatch > 0) ? eachCatch : NUM_EACH_CAPTURE;

        capNum = 0;
        int loopNumTmp = loopNum;
        while (IS_CAPTURE && loopNumTmp > 0 && Pcap.OK == pcap.loop(eachCatch, myhandler, "jNetPcap rocks!")) {
            --loopNumTmp;
            capNum += eachCatch;
            if (1 == loopNumTmp && allTime)
                loopNumTmp = loopNum;
        }

        pcap.close();
        System.out.printf("\njnetpcap closed. capNum = %d\n", capNum);
    }

    public static void startSniff(int seq) {
        startSniff(seq, 10, NUM_EACH_CAPTURE, false);
    }

    public static void startSniff(int seq, int loopNum) {
        startSniff(seq, loopNum, NUM_EACH_CAPTURE, false);
    }

    public static void startSniff(int seq, int loopNum, int eachCatch) {
        startSniff(seq, loopNum, eachCatch, false);
    }

    public static void startSniffAllTime(int seq) {
        startSniff(seq, 10000, NUM_EACH_CAPTURE, true);
    }

    @Override
    public void run() {
        // TODO Auto-generated method stub
        startSniff(0, 30, 20, true);
    }

}
