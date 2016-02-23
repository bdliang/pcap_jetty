package pcap.constant;

/**
 * 用于标明该tcp链接的状态
 * */

public class TcpStatus {

    public static final int NULL_STATUS = 0;
    public static final int HTTP_REQUEST = 1;
    public static final int HTTP_RESPONSE = 2;

    public static final int HANDSHAKE_REQUEST = 10;
    public static final int HANDSHAKE_RESPONSE = 11;
    public static final int START_QUERY = 11;
    public static final int ANSR_QUERY_OK = 12; // 用于resultSet的判断，
                                                // sql查询语句需要服务器返回操作结果, 例如 insert
    public static final int ANSR_QUERY_ERROR = 13;
    public static final int END_QUERY = 14; // 用于resultSet的判断，
                                            // sql查询语句需要服务器返回查询结果, 例如 select
    public static final int MYSQL_QUIT = -1;

}
