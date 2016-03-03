package pcap.constant;

/**
 * 用于标明该tcp链接的状态
 */

public class TcpStatus {

    public static final int NULL_STATUS = 0;

    public static final int HTTP_REQUEST = 1;
    public static final int HTTP_RESPONSE = 2;

    public static final int MYSQL_HANDSHAKE_REQUEST = 10;
    public static final int MYSQL_HANDSHAKE_RESPONSE = 11;
    public static final int MYSQL_QUERY_START = 11;
    public static final int MYSQL_QUERY_ANS_OK = 12; // sql查询语句需要服务器返回操作结果
    public static final int MYSQL_QUERY_ANS_ERROR = 13;
    public static final int MYSQL_QUERY_END = 14; // sql查询语句需要服务器返回查询结果
    public static final int MYSQL_QUIT = -1;

    public static final int MONGODB_QUERY_START = 21;
    public static final int MONGODB_GET_MORE = 22;
    public static final int MONGODB_ANS = 23;

}
