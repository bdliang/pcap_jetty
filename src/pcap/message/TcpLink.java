package pcap.message;

import pcap.constant.BasicConstants;
import pcap.utils.BasicUtils;
import pcap.utils.PropertyUtils;

@Deprecated
public class TcpLink {

    public static final String SEPERATOR = " ";

    private int ipSrc;
    private int ipDst;
    private String typeSrc;
    private int portSrc;
    private int portDst;
    private String typeDst;
    private TcpLinkRecord record;

    private int indexInBuffer;

    private boolean decode;
    private boolean reversed;

    public TcpLink() {
        this(-1, -1, -1, -1);
    }

    /**
     * 定义一个tcp连接 端口号较小的，作为dst
     * */
    public TcpLink(int ipSrc, int portSrc, int ipDst, int portDst) {
        reversed = false;
        if (portSrc < portDst) {
            this.ipSrc = ipDst;
            this.ipDst = ipSrc;
            this.portSrc = portDst;
            this.portDst = portSrc;
            reversed = true;
        } else {
            this.ipSrc = ipSrc;
            this.ipDst = ipDst;
            this.portSrc = portSrc;
            this.portDst = portDst;
        }
        typeSrc = "";
        typeDst = "";
        record = null;
        decode = false;
        indexInBuffer = -1;
    }

    public TcpLink(TcpLink tcp) {
        this.ipSrc = tcp.ipSrc;
        this.portSrc = tcp.portSrc;
        this.typeSrc = tcp.typeSrc;

        this.ipDst = tcp.ipDst;
        this.portDst = tcp.portDst;
        this.typeDst = tcp.typeDst;

        this.decode = tcp.decode;
        this.reversed = tcp.reversed;
        this.indexInBuffer = tcp.indexInBuffer;

        this.record = new TcpLinkRecord(tcp.record);

    }

    public void endTimeSet(long time) {
        this.record.setEndTime(time);
    }

    public void indexInBufferSet(int index) {
        if (index < 0)
            return;
        indexInBuffer = index;
    }

    public boolean isIndexValid() {
        if (indexInBuffer < 0)
            return false;
        return true;
    }

    public void decodeType(int index) {
        boolean isSrcType = true;
        if (index >= BasicConstants.DST_PORT_ENCODE) {
            index &= BasicConstants.DST_PORT_DECODE;
            isSrcType = false;
        }

        if (isSrcType)
            typeSrc = PropertyUtils.AppLayerName(index);
        else
            typeDst = PropertyUtils.AppLayerName(index);

        decode = true;
    }

    public void selfReverse() {
        int tmp;
        tmp = this.ipSrc;
        this.ipSrc = this.ipDst;
        this.ipDst = tmp;

        tmp = this.portSrc;
        this.portSrc = this.portDst;
        this.portDst = tmp;

        String str = null;
        str = this.typeSrc;
        this.typeSrc = this.typeDst;
        this.typeDst = str;

    }

    /**
     * 判断两个tcpLink 上层协议类型是否相同
     * 
     * 因为(1)规定端口号小的作为src; (2)只能判断出一端的协议类型，另一端设置为 “”
     * 
     * 所以两端类型判断的结果只能是
     * 
     * (1) 两端类型相同 , 返回true(2) 有一端类型相同， 另一端不同, 返回false
     * */
    @Deprecated
    public boolean typeDetect(TcpLink tcpLink) {
        if (this.typeSrc == tcpLink.typeSrc && this.typeDst == tcpLink.typeDst)
            return true;
        else
            return false;
    }

    public void morePacket(TcpLink tcpLink) {
        plusFromFlag(tcpLink.reversed);
    }

    public void morePacket(boolean direction) {
        plusFromFlag(direction);
    }

    public void plusFromFlag(boolean reversed) {
        record.plusFromFlag(reversed);
    }

    public void startRecord() {
        this.record = new TcpLinkRecord();
    }

    public String toString() {
        return ipSrc + SEPERATOR + portSrc + SEPERATOR + ipDst + SEPERATOR + portDst + ((null == record) ? "" : record.toString());
    }

    /**
     * 此字符串作为 map<String, TcpLink>的 key
     * */
    public String toString1() {
        return ipSrc + SEPERATOR + portSrc + SEPERATOR + ipDst + SEPERATOR + portDst;
    }

    public static String LinkToString(int ipSrc, int portSrc, int ipDst, int portDst) {
        return ipSrc + SEPERATOR + portSrc + SEPERATOR + ipDst + SEPERATOR + portDst;
    }

    public long ipPairGet() {
        return BasicUtils.ping2Int(ipSrc, ipDst);
    }

    public int portPairGet() {
        return BasicUtils.ping2port(portSrc, portDst);
    }

    public boolean isSameTcp(TcpLink tcp) {
        if (ipPairGet() == tcp.ipPairGet() && portPairGet() == tcp.portPairGet())
            return true;
        return false;
    }

    public void mergeTcpRecord(TcpLink tcp) {
        this.record.mergeTcpRecord(tcp.record);
    }

    public void resetRecord() {
        this.record.reset();
    }

    public int indexInBufferGet() {
        return indexInBuffer;
    }

    // public int getIpSrc() {
    // return ipSrc;
    // }
    //
    // public int getIpDst() {
    // return ipDst;
    // }
    public String getIpSrc() {
        return BasicUtils.intToIp(ipSrc);
    }

    public String getIpDst() {
        return BasicUtils.intToIp(ipDst);
    }

    public String getTypeSrc() {
        return typeSrc;
    }

    public int getPortSrc() {
        return portSrc;
    }

    public int getPortDst() {
        return portDst;
    }

    public String getTypeDst() {
        return typeDst;
    }

    public TcpLinkRecord getRecord() {
        return record;
    }

}
