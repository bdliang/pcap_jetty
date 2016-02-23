package pcap.decode;

public class MysqlLengthEncodedInteger {

    private long value;
    private int length;
    private boolean isError;

    public MysqlLengthEncodedInteger(long value, int length, boolean isError) {
        super();
        this.value = value;
        this.length = length;
        this.isError = isError;
    }

    public long getValue() {
        return value;
    }

    public int getLength() {
        return length;
    }

    public boolean isError() {
        return isError;
    }
}
