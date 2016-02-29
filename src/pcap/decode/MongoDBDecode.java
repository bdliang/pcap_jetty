package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.record.TcpRecord;

public class MongoDBDecode {

    private static final int HEADER_LENGTH = 4 * 4;

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {
        /* 根据ip, port查找 */
    }

}
