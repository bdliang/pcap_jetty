package pcap.decode;

import org.bson.BSONObject;
import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.constant.MongDBCommand;
import pcap.constant.MongDBOpCode;
import pcap.constant.TcpStatus;
import pcap.record.MongoDBCollectionRecord;
import pcap.record.MongoDBCollectionRecord.MongoDBItems;
import pcap.record.TcpRecord;
import pcap.table.MongoDBCollectionTable;
import pcap.utils.BasicUtils;
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

        for (currentOffset = 0; currentOffset + HEADER_LENGTH < payload.length;) {
            currentMongoDBLength = DecodeUtils.litterEndianToInt(payload, 0, 4);
            if (currentMongoDBLength <= HEADER_LENGTH)
                return;
            nextOffset = currentOffset + currentMongoDBLength;
            decode0(payload, record, timeStamp, currentOffset, currentMongoDBLength, clientToServer);
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
    private static void decode0(byte[] payload, TcpRecord record, long timeStamp, int off, int len, boolean clientToServer) {

        if (null == payload || null == record || off < 0 || len < 0 || off + len > payload.length)
            return;
        int opCode = DecodeUtils.litterEndianToInt(payload, off + 12, 4);
        if (!MongDBOpCode.isOpCodeValid(opCode))
            return;

        String collectionName = null;
        MongoDBCollectionRecord mongoRecord = null;

        switch (opCode) {
            case MongDBOpCode.OP_QUERY :
                if (len < 35 || !clientToServer)
                    return;

                collectionName = DecodeUtils.bytesToString(payload, off + 20, len);
                if (BasicUtils.isStringBlank(collectionName))
                    return;
                int endIndex = collectionName.indexOf(MongDBCommand.COMMAND_FLAG);
                MongoDBItems item = null;
                if (-1 != endIndex && endIndex + MongDBCommand.COMMAND_FLAG.length() == collectionName.length()) {
                    collectionName = collectionName.substring(0, endIndex);
                    int bsonLength = DecodeUtils.litterEndianToInt(payload, off + 20 + collectionName.length(), 4);
                    if (bsonLength < 5)
                        return;
                    BSONObject obj = DecodeUtils.bytesToBSONObject(payload, off + 20 + collectionName.length(), bsonLength);
                    if (null == obj)
                        return;
                    String cmd = null;
                    for (String key : obj.keySet()) {
                        for (String command : MongDBCommand.commands) {
                            if (command.equalsIgnoreCase(key)) {
                                cmd = command;
                                break;
                            }
                        }
                    }
                    item = MongoDBItems.parseContentType(cmd);
                } else if (-1 == endIndex) {
                    item = MongoDBItems.FIND;
                } else {
                    return;
                }
                mongoRecord = MongoDBCollectionTable.getInstance().getMongoDBCollectionRecord(record.typeIp(), record.typePort(),
                        collectionName);
                if (null == mongoRecord)
                    return;
                record.setStatus(TcpStatus.MONGODB_QUERY_START);
                record.setTimeStamp(timeStamp);
                mongoRecord.addItem(item);
                record.setInfo(collectionName);
                break;

            case MongDBOpCode.OP_GET_MORE :
                if (len < 34 || !clientToServer)
                    return;

                collectionName = DecodeUtils.bytesToString(payload, off + 20, len);
                if (BasicUtils.isStringBlank(collectionName))
                    return;
                mongoRecord = MongoDBCollectionTable.getInstance().getMongoDBCollectionRecord(record.typeIp(), record.typePort(),
                        collectionName);
                if (null == mongoRecord)
                    return;
                record.setStatus(TcpStatus.MONGODB_GET_MORE);
                record.setTimeStamp(timeStamp);
                mongoRecord.addItem(MongoDBItems.GETMORE);
                record.setInfo(collectionName);
                break;

            case MongDBOpCode.OP_REPLY :
                if (len < 41 || clientToServer)
                    return;
                int status = record.getStatus();
                if (TcpStatus.MONGODB_QUERY_START == status || TcpStatus.MONGODB_GET_MORE == status) {
                    record.setStatus(TcpStatus.MONGODB_ANS);
                    collectionName = record.getInfo();
                    mongoRecord = MongoDBCollectionTable.getInstance().getMongoDBCollectionRecord(record.typeIp(), record.typePort(),
                            collectionName);
                    if (null == mongoRecord)
                        return;
                    mongoRecord.addTimeRecord(timeStamp - record.getTimeStamp());
                    int flags = DecodeUtils.litterEndianToInt(payload, off + 16, 4);
                    if (0 != (flags & MongDBCommand.FLAG_HAVE_ERRORS))
                        mongoRecord.addItem(MongoDBItems.ERROR);
                } else {
                    return;
                }
                break;

            case MongDBOpCode.OP_INSERT :
                if (len < 27 || !clientToServer)
                    return;
                collectionName = DecodeUtils.bytesToString(payload, off + 20, len);
                if (BasicUtils.isStringBlank(collectionName))
                    return;
                mongoRecord = MongoDBCollectionTable.getInstance().getMongoDBCollectionRecord(record.typeIp(), record.typePort(),
                        collectionName);
                if (null == mongoRecord)
                    return;
                mongoRecord.addItem(MongoDBItems.INSERT);
                break;

            case MongDBOpCode.OP_DELETE :
                if (len <= 24 || !clientToServer)
                    return;
                collectionName = DecodeUtils.bytesToString(payload, off + 20, len);
                if (BasicUtils.isStringBlank(collectionName))
                    return;
                mongoRecord = MongoDBCollectionTable.getInstance().getMongoDBCollectionRecord(record.typeIp(), record.typePort(),
                        collectionName);
                if (null == mongoRecord)
                    return;
                mongoRecord.addItem(MongoDBItems.DELETE);
                break;

            case MongDBOpCode.OP_UPDATE :
                if (len < 36 || !clientToServer)
                    return;
                collectionName = DecodeUtils.bytesToString(payload, off + 20, len);
                if (BasicUtils.isStringBlank(collectionName))
                    return;
                mongoRecord = MongoDBCollectionTable.getInstance().getMongoDBCollectionRecord(record.typeIp(), record.typePort(),
                        collectionName);
                if (null == mongoRecord)
                    return;
                mongoRecord.addItem(MongoDBItems.UPDATE);
                break;

            case MongDBOpCode.OP_KILL_CURSORS :
                if (len < 32 || !clientToServer)
                    return;
                break;
            default :
                return;
        }
    }

}
