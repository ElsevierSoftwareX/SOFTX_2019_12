package it.unipr.netsec.ipstack.analyzer;


import org.zoolu.util.DateFormat;

import it.unipr.netsec.ipstack.net.Packet;


/** A packet with its timestamp.
 */
public class PacketDump {

	/** Timestamp */
	long time;
	
	/** Packet */
	Packet pkt;
	
	
	/** Creates a new packet dump.
	 * @param time the packet timestamp, in milliseconds
	 * @param pkt the packet */
	public PacketDump(long time, Packet pkt) {
		this.time=time;
		this.pkt=pkt;
	}
	
	/** Gets timestamp.
	 * @return the packet timestamp, in milliseconds */
	public long getTimestamp() {
		return time;
	}

	/** Gets packet.
	 * @return the packet */
	public Packet getPacket() {
		return pkt;
	}

	@Override
	public String toString() {
		return DateFormat.formatHHmmssSSS(time)+" "+ProtocolAnalyzer.exploreInner(pkt).toString();
	}
	
}
