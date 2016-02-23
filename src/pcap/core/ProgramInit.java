package pcap.core;

public class ProgramInit {

    public static void init() {
        PortMonitorMap.getInstance().loadPortsMapFromFile();
    }

}
