package it.unipr.netsec.ipstack.analyzer;


import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;


/** It captures packet events.
 */
public interface SnifferListener {

	/** When a new packet is captured.
	 * @param sniffer the sniffer that captured the packet
	 * @param pkt the packet */
	public void onPacket(Sniffer sniffer, NetInterface ni, Packet pkt);
}
