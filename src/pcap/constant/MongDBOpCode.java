package pcap.constant;

/**
 * mongdb操作码
 * 
 * @see https://docs.mongodb.org/manual/reference/mongodb-wire-protocol/
 */
public class MongDBOpCode {

    /** Reply to a client request. responseTo is set. */
    public static final int OP_REPLY = 1;

    /** Generic msg command followed by a string. */
    public static final int OP_MSG = 1000;

    /** Update document. */
    public static final int OP_UPDATE = 2001;

    /** Insert new document. */
    public static final int OP_INSERT = 2002;

    /** Formerly used for OP_GET_BY_OID. */
    public static final int RESERVED = 2003;

    /** Query a collection. */
    public static final int OP_QUERY = 2004;

    /** Get more data from a query. See Cursors. */
    public static final int OP_GET_MORE = 2005;

    /** Delete documents. */
    public static final int OP_DELETE = 2006;

    /** Notify database that the client has finished with the cursor. */
    public static final int OP_KILL_CURSORS = 2007;

    /**
     * 判断opCode是否是MongDBOpCode
     * 
     * 目前只需要 OP_REPLY， OP_UPDATE， OP_INSERT， OP_QUERY， OP_GET_MORE， OP_DELETE，
     * OP_KILL_CURSORS
     */
    public static boolean isOpCodeValid(int opCode) {
        switch (opCode) {
            case OP_REPLY :
                // case OP_MSG :
            case OP_UPDATE :
            case OP_INSERT :
                // case RESERVED :
            case OP_QUERY :
            case OP_GET_MORE :
            case OP_DELETE :
            case OP_KILL_CURSORS :
                return true;
            default :
                return false;
        }
    }
}
