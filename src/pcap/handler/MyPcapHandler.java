package pcap.handler;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import pcap.core.PacketMatch;

@SuppressWarnings("hiding")
public class MyPcapHandler<Object> implements PcapPacketHandler<Object> {

    @Override
    public void nextPacket(PcapPacket packet, Object user) {
        PacketMatch packetMatch = PacketMatch.getInstance();
        packetMatch.handlePacket(packet);
    }
}
