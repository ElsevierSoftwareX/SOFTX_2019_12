package it.unipr.netsec.ipstack.dhcp;


import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.io.InterruptedIOException;


/** DhcpMessage is the base class for managing DHCP request and response messages */
public class DhcpMessage {
	
	final static byte MSG_REQUEST=1;
	final static byte MSG_REPLY=2;
	
	/** Discover message code = 1 */
	final public static byte DHCP_DISCOVER=1;
	/** Offer message code = 2 */
	final public static byte DHCP_OFFER=2;
	/** Request message code = 3 */
	final public static byte DHCP_REQUEST=3;
	/** Decline message code = 4 */
	final public static byte DHCP_DECLINE=4;
	/** Ack message code = 5 */
	final public static byte DHCP_ACK=5;
	/** Nack message code = 6 */
	final public static byte DHCP_NACK=6;
	/** Release message code = 7 */
	final public static byte DHCP_RELEASE=7;
	/** Infrom message code = 8 */
	final public static byte DHCP_INFORM=8;
	/** Adv message code = 9 */
	final public static byte DHCP_ADV=9;
	
	
	// *****************************            *****************************
	// ***************************** Attributes *****************************
	// *****************************            *****************************
	
	/** message operation (i.e. type): 1=request, 2=reply */
	byte op;
	/** hardware address type: (eth=1) */
	byte htype; 
	/** hardware address len (eth=6) */
	byte hlen;
	/** num of hops; setted equals to 0 by clients */
	byte hops;
	/** (4 bytes) transaction ID */
	byte[] xid;
	/** (2 bytes) boot elapsed time, filled by client */
	byte[] secs;
	/** (2 bytes) flags (B0000000) with bit B=broadcast */
	byte[] flags;
	/** (4 bytes) in-use client address */
	byte[] ciaddr;
	/** (4 bytes) 'your' address (assigned by the server) */
	byte[] yiaddr;
	/** (4 bytes) next server for bootstrap ( = 0) */
	byte[] siaddr;
	/** (4 bytes) relay agent ( = 0) */
	byte[] giaddr;
	/** (16 bytes) client hardware address */
	byte[] chaddr;
	/** (64 bytes) server name (optional) */
	byte[] sname;
	/** (128 bytes) boot file name ( = 0) */
	byte[] file;
	/** options */
	byte[][] options;
	
	
	// ************************* Private attributes *************************
	
	final private static int MAX_OPTIONS=255;
	
	private String pkt_saddr, pkt_daddr; // packet source and destination addresses
	private int pkt_sport, pkt_dport, pkt_len; // source and destination ports, message length
	
	
	
	// ****************************              ****************************
	// **************************** Constructors ****************************
	// ****************************              ****************************
	
	/** Costructs an empty message */
	public DhcpMessage() {
		options=new byte[MAX_OPTIONS][];
	}

	/** Costructs an new message read from a DatagramSocket */
	public DhcpMessage(DatagramSocket socket) throws java.io.InterruptedIOException {
		options=new byte[MAX_OPTIONS][];
		receive(socket);
	}

	
	// **************************                   *************************
	// ************************** Attribute methods *************************
	// **************************                   *************************

	// -------------------------------------- op code    
	/** Gets the operation */
	public int getOpCode() {
		return op;
	}
	/** Sets the operation */
	public void setOpCode(int code) {
		op=(byte)code;
	}
	/** Gets a string rapresentation of the operation */
	public String stringOpCode() {
		switch (op) {
			case MSG_REQUEST : return "request";
			case MSG_REPLY : return "reply";
			default : return op+"?";
		}
	}
	/** Whether is a REQUEST */
	public boolean isRequest() {
		return op==MSG_REQUEST;
	}
	/** Whether is a REPLY */
	public boolean isReply() {
		return op==MSG_REPLY;
	}

	// -------------------------------------- hardware address type    
	/** Gets the hardware address type */
	public int getHtype() {
		return htype;
	}
	/** Sets the hardware address type */
	public void setHtype(int haddr_type) {
		htype=(byte)haddr_type;
	}

	// -------------------------------------- hardware address len    
	/** Gets the hardware address len */
	public int getHlen() {
		return hlen;
	}
	/** Sets the hardware address len */
	public void setHlen(int haddr_len) {
		hlen=(byte)haddr_len;
	}

	// -------------------------------------- transaction ID    
	/** Gets the transaction ID */
	public byte[] getXid() {
		return xid;
	}
	/** Sets the transaction ID */
	public void setXid(byte[] x_id) {
		xid=x_id;
	}
	/** Gets the hex value of the transaction ID */
	public String stringXid() {
		return Mangle.bytesToHexString(xid);
	}

	// -------------------------------------- client address    
	/** Gets the client address */
	public String getCiaddr() {
		return Mangle.fourBytesToAddress(ciaddr);
	}
	/** Sets the client address */
	public void setCiaddr(String c_iaddr) {
		ciaddr=Mangle.addressToFourBytes(c_iaddr);
	}

	// -------------------------------------- assigned address    
	/** Gets the assigned address */
	public String getYiaddr() {
		return Mangle.fourBytesToAddress(yiaddr);
	}
	/** Sets the assigned address */
	public void setYiaddr(String y_iaddr) {
		yiaddr=Mangle.addressToFourBytes(y_iaddr);
	}

	// -------------------------------------- next server    
	/** Gets the next server address */
	public String getSiaddr() {
		return Mangle.fourBytesToAddress(siaddr);
	}
	/** Sets the next server address */
	public void setSiaddr(String s_iaddr) {
		siaddr=Mangle.addressToFourBytes(s_iaddr);
	}

	// -------------------------------------- client hardware address    
	/** Gets the client hardware address */
	public String getChaddr() {
		return Mangle.bytesToHexString(chaddr,hlen);
	}
	/** Sets the client hardware address */
	public void setChaddr(String c_haddr) {
		chaddr=Mangle.hexStringToBytes(c_haddr,16);
	}

	// -------------------------------------- OPTIONS    
	/** Whether option <i>n</i> is present */
	public boolean hasOption(int n) { return options[n]!=null; }   

	/** Gets the byte array of option <i>n</i> */
	public byte[] getOption(int n) {
		if (hasOption(n)) return options[n];
	  else return null;
	}       
	/** Sets the option <i>n</i> */
	public void setOption(int n, byte[] b) { options[n]=b; }

	/** Sets the option <i>n</i> */
	public void setOption(int n, String str) {
		if (str!=null) {
			if (str.charAt(str.length()-1)!='\0') str+='\0';
			options[n]=str.getBytes();
		}
	}

	// -------------------------------------- option list    
	/** Whether has the option list option */
	public boolean hasOptionList() { return hasOption(55); }
	/** Gets the option list */
	public byte[] getOptionList() { return getOption(55); }
	/** Gets the option list */
	public String stringOptionList() {
		byte[] b=getOption(55);
		String str="";
		for (int i=0; i<b.length; i++) { str+=b[i]; if (i<b.length-1) str+=" "; }
		return str;
	}
	/** Sets the option list */
	public void setOptionList(byte[] list) { setOption(55,list); }
	 
	// -------------------------------------- type    
	/** Whether has the type option (53) */
	public boolean hasType() {
		return hasOption(53);
	}
	/** Gets the type of message */
	public int getType() {
		if (hasType()) return options[53][0];
		else return -1;
	}
	/** Sets the type of message */
	public void setType(int type) {
		options[53]=new byte[1];
		options[53][0]=(byte)type;
		// set also the op code
		switch(type) {
			case DHCP_DISCOVER : case DHCP_INFORM : case DHCP_REQUEST: case DHCP_DECLINE: case DHCP_RELEASE : op=MSG_REQUEST; break;
			case DHCP_OFFER : case DHCP_ACK : case DHCP_NACK: case DHCP_ADV: op=MSG_REPLY; break;
			//default : op=-1;
		}
	}
	/** True if type is equal to <i>type</i> */
	public boolean typeIs(int type) {
		if (hasType()) return options[53][0]==type;
		else return false;
	}
	/** Gets the type of message */
	public String stringType() {
		if (!hasOption(53)) return null;
		switch (options[53][0]) {
			case DHCP_REQUEST : return "REQUEST";
			case DHCP_OFFER : return "OFFER";
			case DHCP_DISCOVER : return "DISCOVER";
			case DHCP_ACK : return "ACK";
			case DHCP_NACK : return "NACK";
			case DHCP_DECLINE : return "DECLINE";
			case DHCP_RELEASE : return "RELEASE";
			case DHCP_INFORM : return "INFORM";
			case DHCP_ADV : return "ADV";
			default : return "none";
		}
	}
	/** Whether is a DHCP_DISCOVER */
	public boolean isDhcpDiscover() { return typeIs(DHCP_DISCOVER); }   
	/** Whether is a DHCP_INFORM */
	public boolean isDhcpInform() { return typeIs(DHCP_INFORM); }   
	/** Whether is a DHCP_OFFER */
	public boolean isDhcpOffer() { return typeIs(DHCP_OFFER); }   
	/** Whether is a DHCP_REQUEST */
	public boolean isDhcpRequest() { return typeIs(DHCP_REQUEST); }   
	/** Whether is a DHCP_ACK */
	public boolean isDhcpAck() { return typeIs(DHCP_ACK); }   
	/** Whether is a DHCP_NACK */
	public boolean isDhcpNack() { return typeIs(DHCP_NACK); }   
	/** Whether is a DHCP_DECLINE */
	public boolean isDhcpDecline() { return typeIs(DHCP_DECLINE); }   
	/** Whether is a DHCP_RELEASE */
	public boolean isDhcpRelease() { return typeIs(DHCP_RELEASE); }   
	/** Whether is a DHCP_ADV */
	public boolean isDhcpAdv() { return typeIs(DHCP_ADV); }   

	// -------------------------------------- domain name          
	/** Whether has domain name option */
	public boolean hasDomainName() { return hasOption(15); }
	/** Sets the domain name */
	public void setDomainName(String name) { setOption(15,name); }
	/** Gets the domain name */
	public String getDomainName() { return Mangle.bytesToString(getOption(15)); }
	
	// -------------------------------------- netmask          
	/** Whether has the netmask option */
	public boolean hasMask() { return hasOption(1); }
	/** Gets the netmask */
	public String getMask() { return Mangle.fourBytesToAddress(getOption(1)); }
	/** Sets the netmask */
	public void setMask(String mask) { setOption(1,Mangle.addressToFourBytes(mask)); }
	
	// -------------------------------------- client ID          
	/** Whether has the client ID option */
	public boolean hasClientId() { return hasOption(61); }
	/** Gets the client ID */
	public String getClientId() { return Mangle.bytesToHexString(getOption(61)); }
	/** Sets the client ID */
	public void setClientId(byte[] client_id) { setOption(61,client_id); }
	/** Sets the client ID */
	public void setClientId(String client_id) { setClientId(Mangle.hexStringToBytes(client_id)); }
	
	// -------------------------------------- class identifier          
	/** Whether has the class identifier option */
	public boolean hasClassId() { return hasOption(60); }
	/** Gets the class identifier */
	public byte[] getClassId() { return getOption(60); }
	/** Sets the class identifier */
	public void setClassId(byte [] class_id) { setOption(60,class_id); } 
	
	// -------------------------------------- requested address          
	/** Whether has the requested address option */
	public boolean hasRequestedAddress() { return hasOption(50); }
	/** Gets the requested address */
	public String getRequestedAddress() { return Mangle.fourBytesToAddress(getOption(50)); }
	/** Sets the requested address */
	public void setRequestedAddress(String requested_addr) { setOption(50,Mangle.addressToFourBytes(requested_addr)); }

	// -------------------------------------- requested paramenters          
	/** Whether has the array of requested paramenters option */
	public boolean hasRequestedParams() { return hasOption(55); }
	/** Gets the array of requested paramenters */
	public byte[] getRequestedParams() { return getOption(55); }
	/** Gets the array of requested paramenters */
	public void setRequestedParams(byte[] codes) { setOption(55,codes); }
	
	// -------------------------------------- server identifier          
	/** Whether has the server identifier option */
	public boolean hasServerIdAddress() { return hasOption(54); }
	/** Gets the server identifier (i.e. the server address) */
	public String getServerIdAddress() { return Mangle.fourBytesToAddress(getOption(54)); }
	/** Sets the server identifier (i.e. the server address) */
	public void setServerIdAddress(String addr) { setOption(54,Mangle.addressToFourBytes(addr)); }
	
	// -------------------------------------- router address          
	/** Whether has the router address option */
	public boolean hasRouter() { return hasOption(3); }
	/** Gets the router address */
	public String getRouter () { return Mangle.fourBytesToAddress(getOption(3)); }
	/** Sets the router address */
	public void setRouter(String addr) { setOption(3,Mangle.addressToFourBytes(addr)); } // per ora solo 1 router
	
	// -------------------------------------- DNS server address          
	/** Whether has the DNS server address option */
	public boolean hasDns() { return hasOption(6); }
	/** Gets the DNS address */
	public String getDns() { return Mangle.fourBytesToAddress(getOption(6)); }
	/** Sets the DNS server address */
	public void setDns(String addr) { setOption(6,Mangle.addressToFourBytes(addr)); } // per ora solo 1 dns
	
	// -------------------------------------- NAI          
	/** Whether has the NAI option */
	public boolean hasNai() { return hasOption(DhcpStack.nai_option); }
	/** Gets the NAI */
	public String getNai() { return Mangle.bytesToString(getOption(DhcpStack.nai_option)); }
	/** Sets the NAI */
	public void setNai(String nai) { setOption(DhcpStack.nai_option,nai); }
	
	// -------------------------------------- SIP server          
	/** Whether has the SIP server option */
	public boolean hasSip() { return hasOption(DhcpStack.sip_option); }
	/** Gets the SIP server */
	public String getSip() { return Mangle.bytesToString(getOption(DhcpStack.sip_option)); }
	/** Sets the SIP server */
	public void setSip(String sip_addr) { setOption(DhcpStack.sip_option,sip_addr); }
	
	// -------------------------------------- lease time          
	/** Whether has the lease time option */
	public boolean hasLeaseTime() { return hasOption(51); }
	/** Gets lease time */
	public long getLeaseTime() { if (hasOption(51)) return Mangle.fourBytesToTime(options[51]); else return 0; }
	/** Sets lease time */
	public void setLeaseTime(long secs) { options[51]=Mangle.timeToFourBytes(secs); }
	
	// -------------------------------------- renewing time          
	/** Whether has the renewing time option */
	public boolean hasRenewingTime() { return hasOption(58); }
	/** Gets renewing time */
	public long getRenewingTime() { if (hasOption(58)) return Mangle.fourBytesToTime(options[58]); else return 0; }
	/** Sets renewing time */
	public void setRenewingTime(long secs) { options[58]=Mangle.timeToFourBytes(secs); }


	// -------------------------------------- rebinding time          
	/** Whether has the rebinding time option */
	public boolean hasRebindingTime() { return hasOption(59); }
	/** Gets rebinding time */
	public long getRebindingTime() { if (hasOption(59)) return Mangle.fourBytesToTime(options[59]); else return 0; }
	/** Sets rebinding time */
	public void setRebindingTime(long secs) { options[59]=Mangle.timeToFourBytes(secs); }


 
	/** Gets the packet source address */
	public String getSourceAddr() { return pkt_saddr; }
	
	/** Gets the packet */
	public String getDestAddr() { return pkt_daddr; }
	
	/** Gets the packet destination address */
	public int getSourcePort() { return pkt_sport; }
	
	/** Gets the packet source port */
	public int getDestPort() { return pkt_dport; }
	
	/** Gets the packet destination port */
	public int getDhcpLength() { return pkt_len; }  
 
 
 
	// ***************************                ***************************
	// *************************** Public methods ***************************
	// ***************************                *************************** 
		
	/** Reads a new message from a DatagramSocket */
	public void receive(DatagramSocket socket) throws InterruptedIOException {
		try {
			byte[] buf = new byte[2000];
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			socket.receive(packet);
			pkt_len=packet.getLength();
			pkt_saddr=packet.getAddress().getHostAddress();
			pkt_sport=packet.getPort();
			pkt_daddr=socket.getLocalAddress().getHostAddress();
			pkt_dport=socket.getLocalPort();
		
			op=buf[0]; htype=buf[1]; hlen=buf[2]; hops=buf[3];
			xid=Mangle.fourBytes(buf,4);
			secs=Mangle.twoBytes(buf,8);
			flags=Mangle.twoBytes(buf,10);
			ciaddr=Mangle.fourBytes(buf,12);
			yiaddr=Mangle.fourBytes(buf,16);
			siaddr=Mangle.fourBytes(buf,20);
			giaddr=Mangle.fourBytes(buf,24);
			chaddr=Mangle.nBytes(16,buf,28);
			sname=Mangle.nBytes(64,buf,44);
			file=Mangle.nBytes(128,buf,108);
			//startoption=fourBytes(buf,236);
			int i=240; // jump the 4 magic numbers
			while (buf[i]!=-1 && i<buf.length) { // !=255
				//System.out.println("b["+i+"]="+buf[i]+"."+buf[i+1]);
				int option_code=buf[i++];
				if (option_code<0) option_code += 256;
				if (option_code!=0) {
					int option_len=buf[i++];
					options[option_code]=Mangle.nBytes(option_len,buf,i);
					i+=option_len;
				}
			}
		}
	 catch (InterruptedIOException ie) { throw ie; }
	 catch (Exception e) { e.printStackTrace(); }
	}
	
	/** Sends the message through a DatagramSocket */
	public void send(DatagramSocket socket, String daddr, int dport) {
		try {
			byte[] buf = new byte[2000];
	
			buf[0]=op; buf[1]=htype; buf[2]=hlen; buf[3]=hops;
			Mangle.copyFourBytes(xid,buf,4);
			Mangle.copyTwoBytes(secs,buf,8);
			Mangle.copyTwoBytes(flags,buf,10);
			Mangle.copyFourBytes(ciaddr,buf,12);
			Mangle.copyFourBytes(yiaddr,buf,16);
			Mangle.copyFourBytes(siaddr,buf,20);
			Mangle.copyFourBytes(giaddr,buf,24);
			Mangle.copyNBytes(16,chaddr,buf,28);
			Mangle.copyNBytes(64,sname,buf,44);
			Mangle.copyNBytes(128,file,buf,108);
			Mangle.copyFourBytes(DhcpStack.magic_cookie,buf,236);
			int i=240; // jump the 4 magic numbers
			for (int opt=0; opt<MAX_OPTIONS; opt++) {
				//do option 53 first, in places of otion 0
				if (opt!=53) { // jump option 53, since it has been already done in place of option 0!
					if (opt==0) opt=53; // do option 53 in place of otion 0
					if (hasOption(opt)) {
						int optlen=options[opt].length;
						buf[i++]=(byte)opt;
						buf[i++]=(byte)optlen;
						Mangle.copyNBytes(optlen,options[opt],buf,i);
						i+=optlen;
						//debug
						//System.out.print(opt+" ");
					}
					if (opt==53) opt=0; // back to option 0
				}
			}
			buf[i++]=(byte)(-1);
			if (i<320) i=320;
		
			//debug
			//System.out.println(" "+daddr+":"+dport);
		
			DatagramPacket packet = new DatagramPacket(buf,i);
			packet.setAddress(InetAddress.getByName(daddr));
			packet.setPort(dport);
			//DatagramSocket socket=new DatagramSocket();
			socket.send(packet);
			pkt_len=packet.getLength();
			pkt_saddr=socket.getLocalAddress().getHostAddress();
			pkt_sport=socket.getLocalPort();
			pkt_daddr=packet.getAddress().getHostAddress();
			pkt_dport=packet.getPort();
	
			//socket.close();
		} catch (Exception e) { e.printStackTrace(); }
	}
	
		
	/** Converts a message into a readable string */
	public String toString() {
		String str;
		// print timestamp and udp socket info
		str=System.currentTimeMillis()+", "
				+getSourceAddr()+":"+getSourcePort()
				+"->"+getDestAddr()+":"+getDestPort()
				+" ("+getDhcpLength()+")\r\n";
		
		// print message type
		str+="type: "+stringType()+" ("+stringOpCode()+")\r\n";
		
		// print main fields
		if (!getCiaddr().equals("0.0.0.0")) str+="client current address (ciaddr): "+getCiaddr()+"\r\n";
		if (!getYiaddr().equals("0.0.0.0")) str+="offered address (yiaddr): "+getYiaddr()+"\r\n";
		if (!getChaddr().equals("")) str+="client hardware address: "+getChaddr()+"\r\n";
		if (!stringXid().equals("")) str+="Transaction id (xid): "+stringXid()+"\r\n";
		
		// print main options
		if (hasRequestedAddress()) str+="requested address: "+getRequestedAddress()+"\r\n";
		if (hasClientId()) str+="client id: "+getClientId()+"\r\n";
		if (hasClassId()) str+="class: "+getClassId()+"\r\n";
		if (hasServerIdAddress()) str+="server address: "+getServerIdAddress()+"\r\n";
		if (hasMask()) str+="mask: "+getMask()+"\r\n";
		if (hasRouter()) str+="router: "+getRouter()+"\r\n";
		if (hasDns()) str+="DNS: "+getDns()+"\r\n";
		if (hasDomainName()) str+="domain name: "+getDomainName()+"\r\n";
		if (hasNai()) str+="NAI: "+getNai()+"\r\n";
		if (hasSip()) str+="SIP server: "+getSip()+"\r\n";
		if (hasLeaseTime()) str+="lease time: "+getLeaseTime()+"\r\n";
		if (hasRebindingTime()) str+="rebinding time: "+getRebindingTime()+"\r\n";
		if (hasRenewingTime()) str+="renewing time: "+getRenewingTime()+"\r\n";
		if (hasOptionList()) str+="otions list: "+stringOptionList()+"\r\n"; 
		//str+="\r\n";  
		return str;
	}
	
}
