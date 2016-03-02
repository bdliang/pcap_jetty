package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.constant.MongDBOpCode;
import pcap.constant.TcpStatus;
import pcap.record.TcpRecord;
import pcap.utils.DecodeUtils;

public class MongoDBDecode {

    /**
     * 在 MongoDB 中，UTF-8 编码的字符串才是合法的。
     */

    private static final int HEADER_LENGTH = 4 * 4;

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {
        /* 根据ip, port查找 */
        if (null == tcp || null == record)
            return;

        byte[] payload = tcp.getPayload();
        if (payload.length <= HEADER_LENGTH)
            return;

        // 判断mongodb连接方向, true表示从client -> server
        boolean clientToServer = (record.typePort() == tcp.destination());

        int currentOffset = 0;
        int nextOffset = 0;
        int currentMongoDBLength = 0;

        for (currentOffset = 0; currentOffset
                + HEADER_LENGTH < payload.length;) {
            currentMongoDBLength = (int) DecodeUtils.litterEndianToLong(payload,
                    0, 4);
            if (currentMongoDBLength <= HEADER_LENGTH)
                return;
            nextOffset = currentOffset + currentMongoDBLength;
            decode0(payload, record, timeStamp, currentOffset,
                    currentMongoDBLength, clientToServer);
            currentOffset = nextOffset;
        }
    }

    /**
     * @param off
     *            起始位置
     * @param len
     *            包括mongdb包头的packetLength
     * @param clientToServer
     *            用来表明该mongo包的方向
     */
    public static void decode0(byte[] payload, TcpRecord record, long timeStamp,
            int off, int len, boolean clientToServer) {

        int opCode = (int) DecodeUtils.litterEndianToLong(payload, off + 12, 4);
        if (!MongDBOpCode.isOpCodeValid(opCode))
            return;

        switch (opCode) {
            case MongDBOpCode.OP_QUERY :
                record.setStatus(TcpStatus.MONGODB_QUERY_START);
                record.setTimeStamp(timeStamp);
                break;
            case MongDBOpCode.OP_GET_MORE :
                record.setStatus(TcpStatus.MONGODB_GET_MORE);
                record.setTimeStamp(timeStamp);
                break;
            case MongDBOpCode.OP_REPLY :
                int status = record.getStatus();
                if (TcpStatus.MONGODB_QUERY_START == status
                        || TcpStatus.MONGODB_GET_MORE == status) {
                    record.setStatus(TcpStatus.MONGODB_ANS);
                } else {
                    return;
                }
                break;
            case MongDBOpCode.OP_INSERT :
                break;
            case MongDBOpCode.OP_DELETE :
                break;
            case MongDBOpCode.OP_UPDATE :
                break;
            case MongDBOpCode.OP_KILL_CURSORS :
                break;
            default :
                return;
        }
    }

}
