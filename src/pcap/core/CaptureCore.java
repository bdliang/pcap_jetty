package pcap.core;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import pcap.constant.BasicConstants;
import pcap.handler.MyPcapHandler;

public class CaptureCore implements Runnable {

    public static String localIp;

    private static long capNum;

    private static boolean IS_CAPTURE = true;

    private static List<PcapIf> allDevs = null;

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

    /**
     * @param deviceSeq
     *            网卡设备编号， getDevices()获得的List<PcapIf>中的序号
     * @param loopNum
     *            抓包循环的次数
     * @param eachCatch
     *            每次抓包循环抓取包的个数
     * @param allTime
     *            是否一直抓包
     */
    public static void startSniff(int deviceSeq, int loopNum, int eachCatch, boolean allTime) {
        if (null == allDevs)
            allDevs = getDevices();
        StringBuilder errbuf = new StringBuilder();
        String deviceName = null;
        if (-1 == deviceSeq) {
            deviceName = "any";
            System.out.printf("\nChoosing ALL DEVICES on your behalf:\n");
        } else {
            PcapIf device = allDevs.get(deviceSeq);
            deviceName = device.getName();
            System.out.printf("\nChoosing '%s' on your behalf:\n",
                    (device.getDescription() != null) ? device.getDescription() : device.getName());

        }

        // int snaplen = Pcap.DEFAULT_SNAPLEN;
        // int flags = Pcap.MODE_PROMISCUOUS;
        // int timeout = BasicConstants.DEFAULT_TIMEOUT;
        // StringBuilder errsb = null;
        Pcap pcap = Pcap.openLive(deviceName, Pcap.DEFAULT_SNAPLEN, Pcap.MODE_PROMISCUOUS, BasicConstants.DEFAULT_TIMEOUT, errbuf);
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
        eachCatch = (eachCatch > 0) ? eachCatch : BasicConstants.NUM_EACH_CAPTURE;

        capNum = 0;
        int loopNumTmp = loopNum;
        while (IS_CAPTURE && loopNumTmp > 0 && Pcap.OK == pcap.loop(eachCatch, myhandler, null)) {
            --loopNumTmp;
            capNum += eachCatch;
            if (1 == loopNumTmp && allTime)
                loopNumTmp = loopNum;
        }

        pcap.close();
        System.out.printf("\njnetpcap closed. capNum = %d\n", capNum);
    }

    /**
     * 限定循环次数抓包(10次循环)
     * 
     * @param deviceSeq
     *            网卡设备编号， getDevices()获得的List<PcapIf>中的序号
     */
    public static void startSniff(int deviceSeq) {
        startSniff(deviceSeq, 10, BasicConstants.NUM_EACH_CAPTURE, false);
    }

    /**
     * 限定循环次数抓包
     * 
     * @param deviceSeq
     *            网卡设备编号， getDevices()获得的List<PcapIf>中的序号
     * @param loopNum
     *            抓包循环的次数
     */
    public static void startSniff(int deviceSeq, int loopNum) {
        startSniff(deviceSeq, loopNum, BasicConstants.NUM_EACH_CAPTURE, false);
    }

    /**
     * 限定循环次数抓包
     * 
     * @param deviceSeq
     *            网卡设备编号， getDevices()获得的List<PcapIf>中的序号
     * @param loopNum
     *            抓包循环的次数
     * @param eachCatch
     *            每次抓包循环抓取包的个数
     */
    public static void startSniff(int deviceSeq, int loopNum, int eachCatch) {
        startSniff(deviceSeq, loopNum, eachCatch, false);
    }

    /**
     * 一直循环抓包
     * 
     * @param deviceSeq
     *            网卡设备编号， getDevices()获得的List<PcapIf>中的序号
     */
    public static void startSniffAllTime(int deviceSeq) {
        startSniff(deviceSeq, 10000, BasicConstants.NUM_EACH_CAPTURE, true);
    }

    @Override
    public void run() {
        // startSniff(0, 30, 20, true);
        startSniffAllTime(1);
    }

}
