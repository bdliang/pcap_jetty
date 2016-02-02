package pcap.message;

@Deprecated
public class TcpLinkRecord {

    private int countSrcDst;
    private int countDstSrc;
    private long startTime;
    private long endTime;

    public TcpLinkRecord() {
        this(System.currentTimeMillis());
    }

    public TcpLinkRecord(TcpLinkRecord record) {
        this.countDstSrc = record.countDstSrc;
        this.countSrcDst = record.countSrcDst;
        this.startTime = record.startTime;
        this.endTime = record.endTime;
    }

    public TcpLinkRecord(long startTime) {
        countSrcDst = 0;
        countDstSrc = 0;
        this.startTime = startTime;;
        this.endTime = startTime;
    }

    public int getCountSrcDst() {
        return countSrcDst;
    }

    public int getCountDstSrc() {
        return countDstSrc;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public void setEndTime(long time) {
        endTime = time;
    }

    public void plusSrcDst() {
        ++countSrcDst;
    }

    public void plusDstSrc() {
        ++countDstSrc;
    }

    /**
     * direction=true时， 正向+1;否则反向+1;
     * 
     * 
     * */
    public void plusFromFlag(boolean direction) {
        if (direction)
            plusSrcDst();
        else
            plusDstSrc();
    }

    /**
     * 往返个数相加
     * 
     * */
    public void mergeTcpRecord(TcpLinkRecord record) {
        if (null == record)
            return;
        this.countSrcDst += record.countSrcDst;
        this.countDstSrc += record.countDstSrc;
        this.endTime = record.endTime;
    }

    public String toString() {
        return "[" + countSrcDst + " " + countDstSrc + " " + startTime + " " + endTime + "]";
    }

    /**
     * 重新开始统计
     * */
    public void reset() {
        countSrcDst = 0;
        countDstSrc = 0;
        long time = System.currentTimeMillis();
        startTime = time;
        endTime = time;
    }

}
