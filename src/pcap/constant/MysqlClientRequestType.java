package pcap.constant;

/**
 * 用来标注 mysql客户端发送的命令包中的命令类型。
 * 
 * 目前只有 COM_QUERY 这个需要关注。代表insert, update, delete, select。
 * 
 * COM_QUERY 是否包括 rollback 和 commit， 有待验证;目前做法是假设包括。
 * 
 * @see http://dev.mysql.com/doc/internals/en/text-protocol.html
 * */

public class MysqlClientRequestType {

    /** （内部线程状态） */
    public static final int COM_SLEEP = 0x00;
    /** 关闭连接 */
    public static final int COM_QUIT = 0x01;
    /** 切换数据库 */
    public static final int COM_INIT_DB = 0x02;
    /** SQL查询请求 */
    public static final int COM_QUERY = 0x03; // 目前这个是解包索要关注的。

    /** 获取数据表字段信息 */
    public static final int COM_FIELD_LIST = 0x04;
    /** 创建数据库 */
    public static final int COM_CREATE_DB = 0x05;
    /** 删除数据库 */
    public static final int COM_DROP_DB = 0x06;
    /** 清除缓存 */
    public static final int COM_REFRESH = 0x07;

    /** 停止服务器 */
    public static final int COM_SHUTDOWN = 0x08;
    /** 获取服务器统计信息 */
    public static final int COM_STATISTICS = 0x09;
    /** 获取当前连接的列表 */
    public static final int COM_PROCESS_INFO = 0x0A;
    /** （内部线程状态） */
    public static final int COM_CONNECT = 0x0B;

    /** 中断某个连接 */
    public static final int COM_PROCESS_KILL = 0x0C;
    /** 保存服务器调试信息 */
    public static final int COM_DEBUG = 0x0D;
    /** 测试连通性 */
    public static final int COM_PING = 0x0E;
    /** （内部线程状态） */
    public static final int COM_TIME = 0x0F;

    /** （内部线程状态） */
    public static final int COM_DELAYED_INSERT = 0x10;
    /** 重新登陆（不断连接 */
    public static final int COM_CHANGE_USER = 0x11;
    /** 获取二进制日志信息 */
    public static final int COM_BINLOG_DUMP = 0x12;
    /** 获取数据表结构信息 */
    public static final int COM_TABLE_DUMP = 0x13;

    /** （内部线程状态） */
    public static final int COM_CONNECT_OUT = 0x14;
    /** 从服务器向主服务器进行注册 */
    public static final int COM_REGISTER_SLAVE = 0x15;
    /** 预处理SQL语句 */
    public static final int COM_STMT_PREPARE = 0x16;
    /** 执行预处理语句 */
    public static final int COM_STMT_EXECUTE = 0x17;

    /** 发送BLOB类型的数据 */
    public static final int COM_STMT_SEND_LONG_DATA = 0x18;
    /** 销毁预处理语句 */
    public static final int COM_STMT_CLOSE = 0x19;
    /** 清除预处理语句参数缓存 */
    public static final int COM_STMT_RESET = 0x1A;
    /** 设置语句选项 */
    public static final int COM_SET_OPTION = 0x1B;

    /** 获取预处理语句的执行结果 */
    public static final int COM_STMT_FETCH = 0x1C;

}
