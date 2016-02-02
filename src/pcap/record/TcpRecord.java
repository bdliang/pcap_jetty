package pcap.record;

import pcap.utils.PropertyUtils;

public class TcpRecord {

    /**
     * 记录tcp连接。由于tcp连接是双向的，这里规定端口小的一方作为dst。但是这里不提供判断端口，以及根据端口大小调整src和dst。
     * 
     * 所以，请在建立对象或传入时自行将src,dst调整。
     * 
     * @see PacketMatch.handleTcp() 这里已经标准化了
     *      而且这里传入的index(标准化后的值)，是用于根据端口号判断类型的索引变量。因为大大大大大部分只能判断出一方的类型
     *      ，所以这个变量的值可以能src , 可能是dst的索引值。 所以根据index的特点，来判断是src还是dst。然后相应赋值。
     * 
     *      typeInde 用来标示 哪一方的类型通过端口号判断出来了。
     * */

    public static final String SEPERATOR = " ";

    /* 用于标明该tcp链接的状态 */
    public static final int NULL_STATUS = 0;
    public static final int HTTP_REQUEST = 1;
    public static final int HTTP_RESPONSE = 2;

    public static final byte TYPE_NULL = 0;
    public static final byte TYPE_SRC = 1;
    public static final byte TYPE_DST = 2;

    private int ipSrc;
    private int ipDst;
    private String typeSrc;
    private int portSrc;
    private int portDst;
    private String typeDst;

    private int status;
    private byte typeIndex;

    private long timeStamp;
    private String info;

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public int getIpSrc() {
        return ipSrc;
    }

    public int getIpDst() {
        return ipDst;
    }

    public String getType() {
        if (TYPE_SRC == typeIndex)
            return typeSrc;
        else if (TYPE_DST == typeIndex)
            return typeDst;
        return "";
    }

    public int getPortSrc() {
        return portSrc;
    }

    public int getPortDst() {
        return portDst;
    }

    public TcpRecord(int ipSrc, int ipDst, int portSrc, int portDst, int index) {
        this.ipSrc = ipSrc;
        this.ipDst = ipDst;
        this.portSrc = portSrc;
        this.portDst = portDst;

        this.typeSrc = null;
        this.typeDst = null;
        decodeType(index);
        this.status = NULL_STATUS;
        this.timeStamp = -1;
        this.info = null;
    }

    /**
     * 识别一端的类型
     * */
    public void decodeType(int index) {
        if (index < 0) {
            this.typeIndex = TYPE_NULL;
            return;
        }

        boolean isSrcType = true;
        if (index >= PropertyUtils.DST_PORT_ENCODE) {
            index &= PropertyUtils.DST_PORT_DECODE;
            isSrcType = false;
        }

        if (isSrcType) {
            typeSrc = PropertyUtils.AppLayerName(index);
            typeIndex = TYPE_SRC;
        }

        else {
            typeDst = PropertyUtils.AppLayerName(index);
            typeIndex = TYPE_DST;
        }

    }
    public void setStatus(int status) {
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public int typeIp() {
        if (TYPE_SRC == typeIndex) {
            return ipSrc;
        } else if (TYPE_DST == typeIndex) {
            return ipDst;
        }
        return 0;
    }

    public int typePort() {
        if (TYPE_SRC == typeIndex) {
            return portSrc;
        } else if (TYPE_DST == typeIndex) {
            return portDst;
        }
        return 0;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }

}
