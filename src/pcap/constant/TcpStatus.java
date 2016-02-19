package pcap.constant;

public class TcpStatus {

    /* 用于标明该tcp链接的状态 */
    public static final int NULL_STATUS = 0;
    public static final int HTTP_REQUEST = 1;
    public static final int HTTP_RESPONSE = 2;

    public static final int IS_HANDSHAKE = 10;
    public static final int START_QUERY = 11;
    public static final int ANSR_QUERY_OK = 12;
    public static final int ANSR_QUERY_ERROR = 13;

}
