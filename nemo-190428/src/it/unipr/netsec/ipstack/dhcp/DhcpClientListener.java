package it.unipr.netsec.ipstack.dhcp;



/** A DhcpClientListener listenes the changes of the client state */    
public interface DhcpClientListener {
	
	/** When the client state moves to DISCOVERING state */
	public void onDiscovering(DhcpClient c);     
	/** When the client state moves to REQUESTING state */
	public void onRequesting(DhcpClient c);  
	/** When the client state moves to BOUND state */
	public void onBound(DhcpClient c, DhcpMessage ack);  
	/** When the client state moves to RENEWING state */
	public void onRenewing(DhcpClient c);
	/** When the client state moves to REBINDING state */
	public void onRebinding(DhcpClient c);  
	/** When the client state moves to MOVED state,
	  * i.e. the client has moved into a new network */
	public void onMoved(DhcpClient c, String nai);  
}
