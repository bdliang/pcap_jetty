package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.record.TcpRecord;

public class Decode {

    /**
     * 所有的decode都从这里调用
     */
    public static void decodePacket(Tcp tcp, TcpRecord record, long timeStamp) {
        if (null == tcp || null == record)
            return;
        String type = record.getType().toLowerCase();
        if (0 == type.length()) {
            return;
        } else if (type.equals("http")) {
            HttpDecode.decode(tcp, record, timeStamp);
        } else if (type.equals("mysql")) {
            MysqlDecode.decode(tcp, record, timeStamp);
        } else if (type.equals("pgsql")) {
        } else if (type.equals("mongodb")) {
            MongoDBDecode.decode(tcp, record, timeStamp);
        } else if (type.equals("thrift")) {
        } else if (type.equals("redis")) {
        } else if (type.equals("ldap")) {
        }
    }

}
