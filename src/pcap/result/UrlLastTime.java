package pcap.result;

public class UrlLastTime {
    private long timeStamp;
    private long time;

    public UrlLastTime(long timeStamp, long time) {
        this.timeStamp = timeStamp;
        this.time = time;
    }

    public long getTimeStamp() {
        return timeStamp;
    }
    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }
    public long getTime() {
        return time;
    }
    public void setTime(long time) {
        this.time = time;
    }

}
