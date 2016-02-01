package pcap.message;

@Deprecated
public class MessagePcap {

    private int ipSrc;
    private int ipDst;
    private int portSrc;
    private int portDst;

    public MessagePcap() {
        this(-1, -1, -1, -1);
    }

    public MessagePcap(int ipSrc, int ipDst, int portSrc, int portDst) {
        this.ipSrc = ipSrc;
        this.ipDst = ipDst;
        this.portSrc = portSrc;
        this.portDst = portDst;
    }

    public String toString() {
        // return "ipSrc=" + ipSrc + " ipDst=" + ipDst + " portSrc=" + portSrc +
        // " portDst=" + portDst;
        return ipSrc + " " + ipDst + " " + portSrc + " " + portDst;
    }
}
