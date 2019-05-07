package it.unipr.netsec.ipstack.dhcp;



/** MessageFactory includes static methods to forge
  * new dhcp request and/or reply messages
  */
public class MessageFactory {
	
	/** Current stack */
	DhcpStack stack;

	final private static byte[] TWO_ZEROS={0,0};
	final private static byte[] FOUR_ZEROS={0,0,0,0};
	final private static byte[] SIXTEEN_ZEROS={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	final private static byte[] B_FLAGS={-128,0};

	/** Costructor */
	public MessageFactory(DhcpStack dhcpstack) {
		stack=dhcpstack;
	}

	/** Returns a default request message */
	protected DhcpMessage createRequest(byte[] xid)  {
		DhcpMessage req=new DhcpMessage();
		req.setOpCode(DhcpMessage.MSG_REQUEST);
		req.setHlen(stack.hlen);
		req.setHtype(stack.htype);
		req.setChaddr(stack.chaddr);
		req.hops=0;
		req.setXid(xid);
		req.secs=TWO_ZEROS;
		req.flags=B_FLAGS;
		req.yiaddr=req.ciaddr=req.giaddr=req.siaddr=FOUR_ZEROS;
		req.sname=Mangle.initBytes(new byte[64],0);
		req.file=Mangle.initBytes(new byte[128],0);
		return req;
	}
			
	/** Returns a default reply message for the current request */
	protected DhcpMessage createReply(DhcpMessage request) {
		DhcpMessage reply=new DhcpMessage();
		reply.setOpCode(DhcpMessage.MSG_REPLY);
		reply.hlen=request.hlen;
		reply.htype=request.htype;
		reply.chaddr=request.chaddr;
		reply.hops=0;
		reply.xid=request.xid;
		reply.secs=request.secs;
		reply.flags=request.flags;
		reply.yiaddr=reply.ciaddr=reply.giaddr=reply.siaddr=FOUR_ZEROS;
		reply.sname=Mangle.stringToBytes(stack.server_address,64);
		reply.file=Mangle.initBytes(new byte[128],0);
		return reply;
	}

	/** Returns a default DHCP_DISCOVER message
	  * <p> xid : dhcp transaction id, selected by the client 
	  * <p> requested_addr : (OPTIONAL) requested ip address, or null 
	  * <p> lease_time : (OPTIONAL) lease time in seconds, or 0 
	  */
	public DhcpMessage createDhcpDiscover(byte[] xid, String requested_addr, long lease_time)  {
		DhcpMessage req=createRequest(xid);
		req.setType(DhcpMessage.DHCP_DISCOVER);
		if (requested_addr!=null) req.setRequestedAddress(requested_addr);
		if (lease_time>0) req.setLeaseTime(lease_time); 
		return req;
	}

	/** Returns a default DHCP_INFORM message
	  * <p> xid : dhcp transaction id, selected by the client 
	  * <p> ciaddr : client's network address
	  */
	public DhcpMessage createDhcpInform(byte[] xid, String ciaddr)  {
		DhcpMessage req=createRequest(xid);
		req.setType(DhcpMessage.DHCP_INFORM);
		//if (ciaddr!=null)
		req.setCiaddr(ciaddr);
		return req;
	}

	/** Returns a default DHCP_REQUEST message
	  * <p> xid : dhcp transaction id, selected by the client 
	  * <p> ciaddr : (OPTIONAL) client's network address for renew/rebind, or null
	  * <p> requested_addr : (OPTIONAL) requested ip address, or null.
	  * MUST in initialization, MUST-NOT in renewing 
	  * <p> lease_time : (OPTIONAL) lease time in seconds, or 0 
	  * <p> server_addr : (OPTIONAL) the server address, or null.
	  * MUST after selecting the offer, MUST-NOT in other cases 
	  */
	public DhcpMessage createDhcpRequest(byte[] xid, String ciaddr, String requested_addr, long lease_time, String server_addr)  {
		DhcpMessage req=createRequest(xid);
		req.setType(DhcpMessage.DHCP_REQUEST);
		if (ciaddr!=null) req.setCiaddr(ciaddr);
		if (requested_addr!=null) req.setRequestedAddress(requested_addr);
		if (lease_time>0) req.setLeaseTime(lease_time); 
		if (server_addr!=null) req.setServerIdAddress(server_addr);
		return req;
	}
	/** Returns a  MHCP_REQUEST message
	  * <p> xid : dhcp transaction id, selected by the client 
	  * <p> server_addr : the server address
	  * <p> nai : the new NAI (from the MHCP ADV)
	  */
	public DhcpMessage createMhcpRequest(byte[] xid, String server_addr, String nai)  {
		DhcpMessage req=createRequest(xid);
		req.setType(DhcpMessage.DHCP_REQUEST);
		req.setServerIdAddress(server_addr);
		req.setNai(nai);
		return req;
	}

	/** Returns a default DHCP_DECLINE message
	  * <p> xid : dhcp transaction id, selected by the client 
	  * <p> requested_addr : requested ip address
	  * <p> server_addr : the server address
	  */
	public DhcpMessage createDhcpDecline(byte[] xid, String requested_addr, String server_addr)  {
		DhcpMessage req=createRequest(xid);
		req.setType(DhcpMessage.DHCP_DECLINE);
		//if (requested_addr!=null)
		req.setRequestedAddress(requested_addr);
		//if (server_addr!=null)
		req.setServerIdAddress(server_addr);
		return req;
	}

	/** Returns a default DHCP_RELEASE message
	  * <p> xid : dhcp transaction id, selected by the client 
	  * <p> ciaddr : client's network address
	  * <p> server_addr : the server address
	  */
	public DhcpMessage createDhcpRelease(byte[] xid, String ciaddr, String server_addr)  {
		DhcpMessage req=createRequest(xid);
		req.setType(DhcpMessage.DHCP_RELEASE);
		//if (ciaddr!=null)
		req.setCiaddr(ciaddr);
		//if (server_addr!=null)
		req.setServerIdAddress(server_addr);
		return req;
	}

	/** Returns a default DHCP_OFFER message
	  * <p> discover : received dhcp discover message
	  * <p> server_addr : the server address
	  * <p> offered_address: the offered address (yiaddr)
	  * <p> lease_time : lease time in seconds 
	  * <p> mask: (OPTIONAL) the mask, or null 
	  * <p> router: (OPTIONAL) the router, or null 
	  * <p> dns: (OPTIONAL) the dns, or null 
	  * <p> domain_name: (OPTIONAL) the domain name, or null 
	  */
	public DhcpMessage createDhcpOffer(DhcpMessage discover, String server_addr, String offered_address, String mask, long lease_time, String router, String dns, String domain_name)  {
		DhcpMessage resp=createReply(discover);
		resp.setType(DhcpMessage.DHCP_OFFER);
		//if (server_addr!=null)
		resp.setServerIdAddress(server_addr);
		//if (offered_address!=null) 
		resp.setYiaddr(offered_address);
		//if (lease_time>0)
		resp.setLeaseTime(lease_time);
		resp.setRebindingTime(lease_time*3/4); 
		resp.setRenewingTime(lease_time/2); 
		if (mask!=null) resp.setMask(mask);
		if (router!=null) resp.setRouter(router);
		if (dns!=null) resp.setDns(dns);
		if (domain_name!=null) resp.setDomainName(domain_name);
		return resp;
	}

	/** Returns a default DHCP_ACK message
	  * <p> request : received dhcp request/inform message
	  * <p> server_addr : the server address
	  * <p> assigned_address: (OPTIONAL) the assigned address (yiaddr)
	  * MUST in response to DHCP_REQUEST, MUST-NOT in response to DHCP_INFORM
	  * <p> lease_time : (OPTIONAL) lease time in seconds, or 0 
	  * MUST in response to DHCP_REQUEST, MUST-NOT in response to DHCP_INFORM
	  * <p> mask: (OPTIONAL) the mask, or null 
	  * <p> router: (OPTIONAL) the router, or null 
	  * <p> dns: (OPTIONAL) the dns, or null 
	  * <p> domain_name: (OPTIONAL) the domain name, or null 
	  */
	public DhcpMessage createDhcpAck(DhcpMessage request, String server_addr, String assigned_address, String mask, long lease_time, String router, String dns, String domain_name)  {
		DhcpMessage resp=createReply(request);
		resp.setType(DhcpMessage.DHCP_ACK);
		//if (server_addr!=null)
		resp.setServerIdAddress(server_addr);
		resp.ciaddr=request.ciaddr;
		if (assigned_address!=null) resp.setYiaddr(assigned_address);
		if (lease_time>0) {
			resp.setLeaseTime(lease_time);
			resp.setRebindingTime(lease_time*3/4); 
			resp.setRenewingTime(lease_time/2); 
		} 
		if (mask!=null) resp.setMask(mask);
		if (router!=null) resp.setRouter(router);
		if (dns!=null) resp.setDns(dns);
		if (domain_name!=null) resp.setDomainName(domain_name);
		return resp;
	}

	/** Returns a default DHCP_NACK message
	  * <p> request : received dhcp request message
	  * <p> server_addr : the server address
	  */
	public DhcpMessage createDhcpNack(DhcpMessage request, String server_addr)  {
		DhcpMessage resp=createReply(request);
		//if (server_addr!=null)
		resp.setServerIdAddress(server_addr);
		resp.setType(DhcpMessage.DHCP_NACK);
		return resp;
	}

	/** Returns a default DHCP_ADV message
	  * <p> server_addr : the server address
	  * <p> nai: the NAI
	  */
	public DhcpMessage createDhcpAdv(String server_addr, String nai)  {
		DhcpMessage msg=new DhcpMessage();
		msg.setOpCode(DhcpMessage.MSG_REPLY);
		msg.setHlen(0);
		msg.setHtype(0);
		msg.setChaddr("");      
		msg.hops=0;
		msg.setXid(FOUR_ZEROS);      
		msg.secs=TWO_ZEROS;
		msg.flags=B_FLAGS;
		msg.yiaddr=msg.ciaddr=msg.giaddr=msg.siaddr=FOUR_ZEROS;
		msg.sname=Mangle.initBytes(new byte[64],0);
		msg.file=Mangle.initBytes(new byte[128],0);      
		msg.setType(DhcpMessage.DHCP_ADV);
		msg.setServerIdAddress(server_addr);
		msg.setNai(nai);
		return msg;
	}

	// *************************** Private methods **************************
	
	private static void printlog(String str, int n) {
		//Log.out.println("MessageFactory: "+str);  
	}
}
