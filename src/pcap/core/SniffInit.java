package pcap.core;

public class SniffInit {

    public static void init() {
        PortMonitorMap.getInstance().loadPortsMapFromFile();
    }

}
