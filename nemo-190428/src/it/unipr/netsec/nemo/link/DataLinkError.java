package it.unipr.netsec.nemo.link;


import it.unipr.netsec.ipstack.net.Packet;


/** Single method interface for getting the packet delay.
 * <p>
 * The delay must not include the transmission delay that should be already taken into account by the output interface.
 */
public interface DataLinkError {

	/** Gets packet error.
	 * @param pkt the original packet
	 * @return the possibly modified packet, or <i>null</i> in case of loss */
	public Packet getPacketError(Packet pkt);
}
