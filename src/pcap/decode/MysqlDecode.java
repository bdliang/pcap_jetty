package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.constant.MysqlCapabilityFlag;
import pcap.constant.MysqlClientRequestType;
import pcap.constant.TcpStatus;
import pcap.record.MysqlServerRecord;
import pcap.record.MysqlServerRecord.MysqlItems;
import pcap.record.TcpRecord;
import pcap.table.MysqlServerTable;
import pcap.utils.BasicUtils;
import pcap.utils.DecodeUtils;

import java.nio.charset.Charset;

public class MysqlDecode {

    private static final int NOT_COMPRESS_HEADER_LENGTH = 4;
    private static final int COMPRESSED_HEADER_LENGTH = 7;

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {
        if (null == tcp || null == record)
            return;

        byte[] payload = tcp.getPayload();
        if (payload.length < 5)
            return;

        // / 如果是加密的, 不解析
        if (record.isSSL())
            return;

        boolean compress = record.isCompress();
        int headerLength = (compress ? COMPRESSED_HEADER_LENGTH : NOT_COMPRESS_HEADER_LENGTH);

        int totalLength = payload.length;
        int currentOffset = 0;
        int nextOffset = 0;
        int currentMysqlLength = 0;

        // 判断mysql连接方向, true表示从client -> server
        boolean clientToServer = (record.typePort() == tcp.destination());

        // 处理多个mysql包在一个tcp， 也适用于1:1的关系。
        for (currentOffset = 0; currentOffset < totalLength - 4;) {
            currentMysqlLength = (int) DecodeUtils.litterEndianToLong(payload, currentOffset, 3);
            nextOffset = currentOffset + headerLength + currentMysqlLength;
            // 如果长度不符合逻辑
            if (nextOffset > totalLength)
                break;
            decode0(payload, currentOffset, currentMysqlLength, record, timeStamp, clientToServer, compress);
            currentOffset = nextOffset;
        }
    }

    /**
     * 
     * @param offset
     *            包括mysql包包头的offset
     * @param mysqlLength
     *            从mysql包包头中解析出该包的长度，即除去包头的长度
     * */
    public static void decode0(byte[] payload, int offset, int mysqlLength, TcpRecord record, long timeStamp, boolean clientToServer,
            boolean compress) {

        int headerLength = (compress ? COMPRESSED_HEADER_LENGTH : NOT_COMPRESS_HEADER_LENGTH);

        if (null == payload || (offset + headerLength + mysqlLength) > payload.length)
            return;

        int seq = BasicUtils.u(payload[offset + 3]);
        int requestType = BasicUtils.u(payload[offset + 4]);
        int decodeOffset = offset + 5; // 目前
        MysqlServerRecord mysqlServerRecord = null;

        if (!clientToServer && 0 == seq) {
            // 表明是handshake.
            decodeHandShakeS2C(payload, offset, mysqlLength, record, timeStamp);
        } else if (0 == seq) {
            // 可能是 query
            if (MysqlClientRequestType.COM_QUERY == requestType) {
                record.setStatus(TcpStatus.START_QUERY);
                record.setTimeStamp(timeStamp);

                // !!!尚未完成需要利用 . record中记录的值来判断字符集
                Charset charSet = DecodeUtils.charSet(record.getCharacterSetCode());
                // !!!尚未完成需要利用 . record中记录的值来判断字符集

                String sql = new String(payload, offset + 4, mysqlLength, charSet);
                int tmpSubLength = (10 > sql.length()) ? sql.length() : 10;
                String sqlSub = sql.substring(0, tmpSubLength).toLowerCase();
                MysqlItems item = null;
                for (MysqlItems t : MysqlItems.values()) {
                    if (sqlSub.startsWith(t.name().toLowerCase())) {
                        item = t;
                        break;
                    }
                }
                if (null == item)
                    return;
                mysqlServerRecord = MysqlServerTable.getInstance().getMysqlServerRecord(record.typeIp(), record.typePort());
                if (null == mysqlServerRecord)
                    return;
                mysqlServerRecord.addItem(item);
            }
        } else if (!clientToServer && 0 != seq) {
            // 可能是server对于query的回复
            if (TcpStatus.START_QUERY != record.getStatus())
                return;
            if (0x00 == requestType) {
                // OK包
                if (TcpStatus.START_QUERY != record.getStatus() || mysqlLength >= 7)
                    return;
                record.setStatus(TcpStatus.ANSR_QUERY_OK);
                mysqlServerRecord = MysqlServerTable.getInstance().getMysqlServerRecord(record.typeIp(), record.typePort());
                if (null == mysqlServerRecord)
                    return;
                mysqlServerRecord.addTimeRecord(timeStamp - record.getTimeStamp());
            } else if (0xff == requestType) {
                // ERROR包
                mysqlServerRecord = MysqlServerTable.getInstance().getMysqlServerRecord(record.typeIp(), record.typePort());
                if (null == mysqlServerRecord)
                    return;
                mysqlServerRecord.addItem(MysqlItems.ERROR);
            } else {
                // 可能是resultSet
                if (TcpStatus.START_QUERY != record.getStatus())
                    return;
                mysqlServerRecord = MysqlServerTable.getInstance().getMysqlServerRecord(record.typeIp(), record.typePort());
                record.setStatus(TcpStatus.END_QUERY);
                if (null == mysqlServerRecord)
                    return;
                mysqlServerRecord.addTimeRecord(timeStamp - record.getTimeStamp());
            }
        } else if (clientToServer && 1 == seq) {
            // 可能是客户端回复handshake
            // decodeHandShakeC2S();
        }

    }

    public static void decodeHandShakeS2C(byte[] payload, int offset, int length, TcpRecord record, long timeStamp) {
        if (null == payload || null == record || ((offset + length) > payload.length))
            return;
        record.setStatus(TcpStatus.START_HANDSHAKE);
        record.setTimeStamp(timeStamp);
    }

    public static void decodeHandShakeC2S(byte[] payload, int offset, int length, TcpRecord record, long timeStamp) {
        if (null == payload || null == record || ((offset + length) > payload.length))
            return;
        if (TcpStatus.START_HANDSHAKE != record.getStatus())
            return;
        record.setStatus(TcpStatus.END_HANDSHAKE);
        boolean mysqlProtocol41 = false;
        long capabilityFlags = DecodeUtils.litterEndianToLong(payload, offset, 2);
        if (0L != (MysqlCapabilityFlag.CLIENT_PROTOCOL_41 & capabilityFlags)) {
            mysqlProtocol41 = true;
        }

        if (0L != (MysqlCapabilityFlag.CLIENT_COMPRESS & capabilityFlags)) {
            record.setCompress(true);
        }

        if (0L != (MysqlCapabilityFlag.CLIENT_SSL & capabilityFlags)) {
            record.setSSL(true);
        }

        if (mysqlProtocol41)
            record.setCharacterSetCode(BasicUtils.u(payload[offset + NOT_COMPRESS_HEADER_LENGTH + 8]));
    }

}
