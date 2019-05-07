package it.unipr.netsec.ipstack.ip6;



/** Receiver for all incoming IP packets.
 */
public interface Ip6NodeListener {

	/** When a new packet is received for this node.
	 * @param ip_node the IP node
	 * @param ip_pkt the received packet */
	public void onIncomingPacket(Ip6Node ip_node, Ip6Packet ip_pkt);

}
