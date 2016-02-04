package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.record.TcpRecord;

public class MysqlDecode {

    public static final int BYTETOVALUE = 0x00ff;

    public static final int MYSQL_QUERY = 0x03;

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {

        byte[] payload = tcp.getPayload();
        if (payload.length < 4)
            return;

        long pLength = packetLength(payload[0], payload[1], payload[2]);
        int seq = u(payload[3]);

    }

    /**
     * 将byte型按位转换成相应无符号整数值
     * */
    private static int u(byte b) {
        return (b >= 0) ? b : b + 256;
    }

    /**
     * 将3个byte按位拼成一个long， b1是最高位，b2次之，b3是最低位
     * */
    private static long packetLength(byte b1, byte b2, byte b3) {
        return (((u(b1) << 8) | u(b2)) << 8) | u(b3);
    }
}
