package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.constant.MysqlClientRequestType;
import pcap.record.TcpRecord;
import pcap.utils.DecodeUtils;

public class MysqlDecode {

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {

        if (null == tcp || null == record)
            return;

        byte[] payload = tcp.getPayload();
        if (payload.length < 5)
            return;

        int totalLength = payload.length;
        int currentOffset = 0;
        int nextOffset = 0;
        int currentLength = 0;

        /**
         * 假设 对于和3306连接的端口号 > 3306
         * */
        boolean clientToServer = (record.typePort() == tcp.source());

        // 处理多个mysql包在一个tcp， 也适用于1:1的关系。
        for (currentOffset = 0; currentOffset < totalLength - 4;) {
            currentLength = (int) DecodeUtils.litterEndianToLong(payload, currentOffset, 3);
            nextOffset = currentOffset + 4 + currentLength;
            // 如果长度不符合逻辑
            if (nextOffset > totalLength)
                break;
            decode0(payload, currentOffset, currentLength, record, timeStamp, clientToServer);
            currentOffset = nextOffset;
        }
    }

    public static void decode0(byte[] payload, int offset, int length, TcpRecord record, long timeStamp, boolean direction) {

        if (null != payload || (offset + 4 + length) > payload.length)
            return;

        int seq = u(payload[offset + 3]);
        int requestType = u(payload[offset + 4]);
        int decodeOffset = offset + 5; // 目前

        if (0 == seq) {
            if (MysqlClientRequestType.COM_QUERY == requestType) {
                String s = new String();
            }
        }
    }

    public static void decodeHandShake(Tcp tcp, TcpRecord record, long timeStamp, int offset, int length) {

    }

    /**
     * 将byte型按位转换成相应无符号整数值
     * */
    private static int u(byte b) {
        return 0xff & b;
    }

}
