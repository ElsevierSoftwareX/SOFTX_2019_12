package it.unipr.netsec.ipstack.ip4;



/** Receiver for all incoming IP packets.
 */
public interface Ip4NodeListener {

	/** When a new packet is received for this node.
	 * @param ip_node the IP node
	 * @param ip_pkt the received packet */
	public void onIncomingPacket(Ip4Node ip_node, Ip4Packet ip_pkt);

}
