package pcap.record;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;

/**
 * 用来记录客户端连接状态的。
 * 
 * 例如 : 是否压缩，使用的字符集，是否使用SSL等选项。
 * 
 * 将来可能会用到
 * */

@Deprecated
public class MysqlClientRecord {

    // 用于转化json时字段控制
    public static final JsonConfig config = new JsonConfig();
    static {
        config.setExcludes(null);
    }

    private int ip;
    private int port;

    private int ipServer;
    private int portServer;

    private int status; // 参照TcpStatus类

    private boolean isCompress;
    private boolean isSSL;
    private int characterSetCode;

    public MysqlClientRecord(int ip, int port, int ipServer, int portServer) {
        super();
        this.ip = ip;
        this.port = port;
        this.ipServer = ipServer;
        this.portServer = portServer;

        isCompress = false;
        isSSL = false;
        // pcap.constant.MysqlCharacterSet中定义
        characterSetCode = -1;
    }

    /** getter & setter */
    public int getIpServer() {
        return ipServer;
    }

    public void setIpServer(int ipServer) {
        this.ipServer = ipServer;
    }

    public int getPortServer() {
        return portServer;
    }

    public void setPortServer(int portServer) {
        this.portServer = portServer;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public boolean isCompress() {
        return isCompress;
    }

    public void setCompress(boolean isCompress) {
        this.isCompress = isCompress;
    }

    public boolean isSSL() {
        return isSSL;
    }

    public void setSSL(boolean isSSL) {
        this.isSSL = isSSL;
    }

    public int getCharacterSetCode() {
        return characterSetCode;
    }

    public void setCharacterSetCode(int characterSetCode) {
        this.characterSetCode = characterSetCode;
    }

    public int getIp() {
        return ip;
    }

    public int getPort() {
        return port;
    }
    /** getter & setter */

    @Override
    public String toString() {
        return JSONObject.fromObject(this).toString();
    }

}
