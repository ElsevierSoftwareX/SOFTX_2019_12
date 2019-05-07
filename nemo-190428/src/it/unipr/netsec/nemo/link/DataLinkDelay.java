package it.unipr.netsec.nemo.link;


import it.unipr.netsec.ipstack.net.Packet;


/** Single method interface for getting the packet delay.
 * <p>
 * The delay must not include the transmission delay that should be already taken into account by the output interface.
 */
public interface DataLinkDelay {

	/** Gets packet delay.
	 * @param pkt the packet
	 * @return packet delay in nanoseconds */
	public long getPacketDelay(Packet pkt);
}
