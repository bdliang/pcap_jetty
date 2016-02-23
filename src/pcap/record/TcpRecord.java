package pcap.record;

import net.sf.json.JsonConfig;
import pcap.constant.MysqlCharacterSet;
import pcap.constant.TcpStatus;
import pcap.core.PortMonitorMap;
import pcap.utils.BasicUtils;

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

    // 用于转化json时字段控制
    public static final JsonConfig config = new JsonConfig();
    static {
        // 只要设置这个数组，指定过滤哪些字段。
        config.setExcludes(new String[]{"info", "type", "timeStamp"});
    }

    /** 如果找到时，需要返回对应的应用索引。这里用来区别是src的应用类型，或者是des的应用类型 */
    private static final int DST_PORT_ENCODE = 0x40000000;
    private static final int DST_PORT_DECODE = 0x3fffffff;

    private static final byte TYPE_NULL = 0;
    private static final byte TYPE_SRC = 1;
    private static final byte TYPE_DST = 2;

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

    /**
     * mysql使用， 用来记录mysql连接的压缩，加密，字符集属性。
     * 
     * 默认值 不压缩，不加密， latin1的字符集
     * 
     * @see MysqlCharacterSet
     * */
    private boolean Compress;
    private boolean SSL;
    private int characterSetCode; // 用于记录mysql的字符集

    public TcpRecord(int ipSrc, int portSrc, int ipDst, int portDst, int index) {
        this.ipSrc = ipSrc;
        this.ipDst = ipDst;
        this.portSrc = portSrc;
        this.portDst = portDst;

        this.typeSrc = null;
        this.typeDst = null;
        decodeType(index);
        this.status = TcpStatus.NULL_STATUS;
        this.timeStamp = -1;
        this.info = null;

        Compress = false;
        SSL = false;
        characterSetCode = 0x08;
    }

    /**
     * 识别一端的类型
     * */
    private void decodeType(int index) {
        if (index < 0) {
            this.typeIndex = TYPE_NULL;
            return;
        }

        boolean isSrcType = true;
        if (index >= DST_PORT_ENCODE) {
            index &= DST_PORT_DECODE;
            isSrcType = false;
        }

        if (isSrcType) {
            typeSrc = PortMonitorMap.getInstance().AppLayerName(index);
            typeIndex = TYPE_SRC;
        } else {
            typeDst = PortMonitorMap.getInstance().AppLayerName(index);
            typeIndex = TYPE_DST;
        }
    }

    public String getType() {
        if (TYPE_SRC == typeIndex)
            return typeSrc;
        else if (TYPE_DST == typeIndex)
            return typeDst;
        return "";
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

    public int getPortSrc() {
        return portSrc;
    }

    public int getPortDst() {
        return portDst;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public boolean isCompress() {
        return Compress;
    }

    public void setCompress(boolean compress) {
        Compress = compress;
    }

    public boolean isSSL() {
        return SSL;
    }

    public void setSSL(boolean sSL) {
        SSL = sSL;
    }

    public int getCharacterSetCode() {
        return characterSetCode;
    }

    public void setCharacterSetCode(int characterSetCode) {
        this.characterSetCode = characterSetCode;
    }

    /** 是否符合Encode条件需要自己判断，本函数不提供条件判断 */
    public static int EnCode(int i) {
        return i | DST_PORT_ENCODE;
    }

    // public static int DeCode(int i) {
    // return i & DST_PORT_DECODE;
    // }

    @Override
    public String toString() {
        return "[src:" + BasicUtils.intToIp(ipSrc) + "." + portSrc + " dst:" + BasicUtils.intToIp(ipDst) + "." + portDst + " type:"
                + this.getType() + "]";
    }
}
