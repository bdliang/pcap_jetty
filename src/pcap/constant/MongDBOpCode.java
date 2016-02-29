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

}
