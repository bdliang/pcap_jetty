package pcap.constant;

public class BasicConstants {

    /** 用于端口号查找时的返回值 */
    public static final int WRONG_ARGUMENT = -3;
    public static final int APP_NOT_FOUND = -2;
    public static final int NOT_FOUND = -1;
    public static final int OK_FOUND = 0;
    public static final int OK_FOUND_SRC = 1;
    public static final int OK_FOUND_DST = 2;

    /** jNetPcap 使用的常量 */
    public static final int NUM_EACH_CAPTURE = 10;
    public static final int DEFAULT_TIMEOUT = 500; // 单位是毫秒

    /** task类 使用的常量 */
    public static final long SECONDS_OF_A_DAY = 24 * 60 * 60L;
    public static final int DEFAULT_CLEAN_DELAY = 30; // 单位是 秒
    public static final int DEFAULT_CLEAN_INTERVAL = 30; // 单位是 秒

    public static final int MYSQL_DEFAULT_CHARACTER_SET_CODE = 0x08;// latin1

    public static final String NULL_JSON_RETURN = "{}";

}
