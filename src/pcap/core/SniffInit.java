package pcap.core;

import java.util.Arrays;

import pcap.constant.MongDBCommand;

public class SniffInit {

    public static void init() {
        PortMonitorMap.getInstance().loadPortsMapFromFile();
        Arrays.sort(MongDBCommand.commands);
    }

}
