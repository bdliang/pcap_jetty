package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import java.nio.charset.Charset;

import pcap.constant.MysqlCapabilityFlag;
import pcap.constant.MysqlClientRequestType;
import pcap.constant.TcpStatus;
import pcap.record.MysqlServerRecord;
import pcap.record.MysqlServerRecord.MysqlItems;
import pcap.record.TcpRecord;
import pcap.table.MysqlServerTable;
import pcap.utils.BasicUtils;
import pcap.utils.CompressUtils;
import pcap.utils.DecodeUtils;

public class MysqlDecode {

    private static final int NOT_COMPRESS_HEADER_LENGTH = 4;
    private static final int COMPRESSED_HEADER_LENGTH = 7;

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {
        if (null == tcp || null == record)
            return;

        byte[] payload = tcp.getPayload();
        if (payload.length <= NOT_COMPRESS_HEADER_LENGTH)
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
            currentMysqlLength = DecodeUtils.litterEndianToInt(payload, currentOffset, 3);
            nextOffset = currentOffset + headerLength + currentMysqlLength;
            // 如果长度不符合逻辑
            if (nextOffset > totalLength)
                break;
            decode0(payload, currentOffset, currentMysqlLength, record, timeStamp, clientToServer, compress);
            currentOffset = nextOffset;
        }
    }

    /**
     * 解析一个完整的包。 如果是一个压缩的包，那么根据压缩的详细规则去解压缩，然后再去解析。
     * 
     * compress == true; compressed packet header包含3部分，共7字节;
     * 
     * a. 3 : 该压缩包的payload, 即该压缩包总字节数 - 7;
     * 
     * b. 1 : 该压缩包的seq,与非压缩包的seq不同;
     * 
     * c. 3 : 该压缩包解压后的字节数, 包括mysql packet header的3个字节, 会用多个包压缩成一个包。
     * 
     * 如果 c中的3个字节是 0x 00 00 00的话， 表明内容不符合压缩条件或者压缩失败， 是非压缩的。按照字符集解压。
     * 
     * @param payload
     *            数据包所在数组
     * @param offset
     *            包括mysql包包头的offset
     * @param mysqlLength
     *            从mysql包包头中解析出该包的长度，即除去包头的长度
     * @param record
     *            对应TcpRecord
     * @param timeStamp
     *            pcap抓包时间点
     * @param clientToServer
     *            用来表明该mysql包的方向
     * @param compress
     *            用来表明该mysql包是否是压缩后的包
     * 
     */
    private static void decode0(byte[] payload, int offset, int mysqlLength, TcpRecord record, long timeStamp, boolean clientToServer,
            boolean compress) {

        int headerLength = (compress ? COMPRESSED_HEADER_LENGTH : NOT_COMPRESS_HEADER_LENGTH);

        if (null == payload || null == record || offset < 0 || mysqlLength <= 0 || (offset + headerLength + mysqlLength) > payload.length)
            return;

        int unCompressedLength = 0;
        if (compress) {
            if (0L != (unCompressedLength = DecodeUtils.litterEndianToInt(payload, offset + NOT_COMPRESS_HEADER_LENGTH, 3))) {
                payload = CompressUtils.zlibDecompress(payload, offset + COMPRESSED_HEADER_LENGTH, mysqlLength);
                if (null == payload || payload.length != unCompressedLength)
                    return;
                offset = 0;
                mysqlLength = DecodeUtils.litterEndianToInt(payload, offset, 3);
            }
        }

        /**
         * 解压缩后的数据， 也可能包括多个包。不过不需要解析之后的包。
         * 
         * 如果需要，参考 MysqlDecode.decode();
         * 
         */

        int seq = BasicUtils.u(payload[offset + 3]);
        int requestType = BasicUtils.u(payload[offset + headerLength]);
        MysqlServerRecord mysqlServerRecord = MysqlServerTable.getInstance().getMysqlServerRecord(record.typeIp(), record.typePort());
        if (null == mysqlServerRecord)
            return;

        if (!clientToServer && 0 == seq) {
            // 表明是handshake.
            record.setStatus(TcpStatus.MYSQL_HANDSHAKE_REQUEST);
        } else if (clientToServer && 0 == seq) {
            // 可能是 query
            if (MysqlClientRequestType.COM_QUERY == requestType) {
                record.setStatus(TcpStatus.MYSQL_QUERY_START);
                record.setTimeStamp(timeStamp);

                // !!!尚未完成需要利用 . record中记录的值来判断字符集
                Charset charSet = DecodeUtils.charSet(record.getCharacterSetCode());
                // !!!尚未完成需要利用 . record中记录的值来判断字符集

                String sql = new String(payload, offset + headerLength + 1, (mysqlLength - 1 > 100) ? 100 : mysqlLength - 1, charSet);
                int tmpSubLength = (10 > sql.length()) ? sql.length() : 10;
                String sqlSub = sql.substring(0, tmpSubLength).toLowerCase();
                MysqlItems item = null;
                for (MysqlItems t : MysqlItems.values()) {
                    if (sqlSub.startsWith(t.name().toLowerCase())) {
                        item = t;
                        break;
                    }
                }
                if (null == item || MysqlItems.OTHER == item)
                    return;
                mysqlServerRecord.addItem(item);
            } else if (MysqlClientRequestType.COM_QUIT == requestType) {
                // 因为记录mysql ssl, compress，
                // charset选项的是TcpRecord，每个对象记录在TcpTable中，TcpTable会定时清理，所以当一个mysql连接跨越1个监测周期时，如果有compress,ssl,char
                // set等非默认的选项时，
                // 会出现不能正确解包的情况。所以可能需要把不是默认选项的mysql的连接单独记录。这里用来识别mysql
                // client主动断开连接时，与server通信的情况。可用来将对应的mysql单独记录删除。
                record.setStatus(TcpStatus.MYSQL_QUIT);
            }

        } else if (!clientToServer && 0 != seq) {
            // 可能是server对于query的回复
            if (TcpStatus.MYSQL_QUERY_START != record.getStatus())
                return;
            if (0x00 == requestType) {
                // OK包
                record.setStatus(TcpStatus.MYSQL_QUERY_ANS_OK);
                mysqlServerRecord.addTimeRecord(timeStamp - record.getTimeStamp());
            } else if (0xff == requestType) {
                // ERROR包
                record.setStatus(TcpStatus.MYSQL_QUERY_ANS_ERROR);
                mysqlServerRecord.addItem(MysqlItems.ERROR);
                mysqlServerRecord.addTimeRecord(timeStamp - record.getTimeStamp());
            } else {
                // resultSet
                record.setStatus(TcpStatus.MYSQL_QUERY_END);
                mysqlServerRecord.addTimeRecord(timeStamp - record.getTimeStamp());
            }
        } else if (clientToServer && 1 == seq) {
            // 可能是客户端回复handshake
            decodeHandShakeC2S(payload, offset, mysqlLength, record, timeStamp);
        }

    }
    /**
     * 
     * @param offset
     *            包括mysql包包头的offset
     * @param mysqlLength
     *            从mysql包包头中解析出该包的长度，即除去包头的长度
     */
    private static void decodeHandShakeC2S(byte[] payload, int offset, int mysqlLength, TcpRecord record, long timeStamp) {
        if (null == payload || null == record || offset < 0 || mysqlLength <= 0 || ((offset + mysqlLength) > payload.length))
            return;
        if (TcpStatus.MYSQL_HANDSHAKE_REQUEST != record.getStatus())
            return;
        record.setStatus(TcpStatus.MYSQL_HANDSHAKE_RESPONSE);
        boolean mysqlProtocol41 = false;
        int capabilityFlags = DecodeUtils.litterEndianToInt(payload, offset + NOT_COMPRESS_HEADER_LENGTH, 2);
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
