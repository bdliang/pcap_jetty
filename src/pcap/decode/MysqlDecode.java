package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

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

        // 判断mysql连接方向, true表示从client -> server
        boolean clientToServer = (record.typePort() == tcp.destination());

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

    public static void decode0(byte[] payload, int offset, int length, TcpRecord record, long timeStamp, boolean clientToServer) {

        if (null == payload || (offset + 4 + length) > payload.length)
            return;

        int seq = BasicUtils.u(payload[offset + 3]);
        int requestType = BasicUtils.u(payload[offset + 4]);
        int decodeOffset = offset + 5; // 目前
        MysqlServerRecord mysqlServerRecord = null;

        if (!clientToServer && 0 == seq) {
            // 表明是handshake.
            decodeHandShakeS2C(payload, offset, length, record, timeStamp);
        } else if (0 == seq) {
            // 可能是 query
            if (MysqlClientRequestType.COM_QUERY == requestType) {
                record.setStatus(TcpStatus.START_QUERY);
                record.setTimeStamp(timeStamp);

                // !!!尚未完成需要利用 . record中记录的值来判断字符集
                Charset charSet = DecodeUtils.charSet(record.getCharacterSetCode());
                // !!!尚未完成需要利用 . record中记录的值来判断字符集

                String sql = new String(payload, offset, length, charSet);
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
                if (TcpStatus.START_QUERY != record.getStatus())
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
        } else if (clientToServer && 0 != seq) {
            // 可能是客户端回复handshake
            ;
        }

    }
    public static void decodeHandShakeS2C(byte[] payload, int offset, int length, TcpRecord record, long timeStamp) {
        if (null == payload || null == record || ((offset + length) > payload.length))
            return;
        record.setStatus(TcpStatus.START_HANDSHAKE);
        record.setTimeStamp(timeStamp);
    }

    public static void decodeHandShakeC2S(byte[] payload, int offset, int length, TcpRecord record, long timeStamp) {
        record.setStatus(TcpStatus.START_HANDSHAKE);
        record.setTimeStamp(timeStamp);

    }

}
