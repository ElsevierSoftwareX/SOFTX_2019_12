package it.unipr.netsec.ipstack.dhcp;


import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.io.*;
import java.util.Set;
import java.util.HashSet;
import java.util.Hashtable;


/** Class DhcpServer implements a simple state-less DHCP or MHCP server. */
public class DhcpServer extends Thread {
	
	/** Message Log (for debugging) */
	Logger messagelog;    

	/** Current DhcpStack */
	DhcpStack stack;

	/** Current MessageFactory */
	MessageFactory msgfactory;

	/** udp socket */
	DatagramSocket socket;  
	/** udp socket used as source_socket in case of option "specific_source_socket" is used */
	DatagramSocket source_socket;
	

	// dhcp attributes   
	String server_addr;
	//String assigned_addr;
	//String assigned_mask;
	String assigned_router;
	String assigned_dns;
	String domain_name;
	String nai;
	String sip_server;

	/** stop flag */
	boolean stop;

	/** running flag */
	boolean running=false;
	
	/** available addresses */
	Set available_addresses;
	/** net masks associated to each address (address is the hashtable key) */
	Hashtable masks;
	/** assigned addresses */
	AddressDatabase assigned_addresses;
	
 
	/** Constructs the server */
	public DhcpServer(DhcpStack dhcpstack, DatagramSocket udpsocket) {
		
		stack=dhcpstack;
		msgfactory=new MessageFactory(stack);
		socket=udpsocket;
		source_socket=socket;
		if (stack.source_socket_patch) {
			try { source_socket=new DatagramSocket(stack.server_port+10,InetAddress.getByName(stack.server_address)); } catch (Exception e) { e.printStackTrace(); } 
		}
		// init assigned values
		server_addr=stack.server_address;
		assigned_router=stack.router;
		assigned_dns=stack.dns;
		domain_name=stack.domain_name;
		nai=stack.nai;
		sip_server=stack.sip_server;
		
		// init the set of available addresses
		available_addresses=new HashSet();
		masks=new Hashtable();
		assigned_addresses=new AddressDatabase();
		String address_log="Available addresses: ("+stack.available_addresses.length+")";
		for (int i=0; i<stack.available_addresses.length; i++) {
			String complete_address=stack.available_addresses[i];
		int indexofslash=complete_address.indexOf("/");
		String addr=complete_address.substring(0,indexofslash);
		String mask=complete_address.substring(indexofslash+1);
		available_addresses.add(addr);
		masks.put(addr,mask);
		address_log+="\naddress="+addr+"\t"+"mask="+mask;
		}
		SystemUtils.getDefaultLogger().log(LoggerLevel.INFO,getClass(),address_log);

		messagelog=new LoggerWriter(stack.log_path+"//server-"+stack.server_port+".log",LoggerLevel.INFO); 
	}
	
	/** Moves expired addresses from 'assigned_addresses' set
	  * to the 'available_addresses' set */ 
	private void freeExpiredAddresses() {
			String addr;
		while ((addr=assigned_addresses.getExpiredAddress())!=null) {
			available_addresses.add(addr);
			assigned_addresses.remove(addr);
		}
	}
	
	/** The Thread.run() method */
	public void run() {
		server();
	}
	
	/** Stops the server */
	public void halt() {
		stop=true;
		printlog("Halting DHCP server...",LoggerLevel.INFO);
	}
		
	/** Whether the server is active */
	public boolean isRunning() {
		return running;
	}

	/** The main server method, invoked by the run() thread */
	public void server() {
		
		stop=false;
		running=true;
				
		// make the socket non-blocking
		try {
			// if no packet is received after 2sec, throughs an InterruptedIOException
			socket.setSoTimeout(2000);
		}
		catch (Exception e) { e.printStackTrace(); }


		while(!stop) {
			
			DhcpMessage message;
			try {
				message=new DhcpMessage(socket);
			}
			catch (InterruptedIOException ie) { continue; }
			printmessagelog(message);
			System.out.println("DEBUG: DhcpServer: server()");
			
			if (message.isRequest()) {
				DhcpMessage reply=null;
					
				if (message.isDhcpDiscover()) reply=handleDiscover(message); 
				if (message.isDhcpRequest()) reply=handleRequest(message);                      
				if (message.isDhcpRelease()) reply=handleRelease(message); 
				if (message.isDhcpInform()) reply=handleInform(message); 
						  
				if (reply!=null) {
					String d_addr=stack.broadcast_address;
					int d_port=stack.client_port;
					
					// Patch for running DhcpServer on the client host.
					//    Note that if no address is set for the local host, 
					//    no packet is sent to d_addr=255.255.255.255
					//    (or to any other external addresses);
					//    hence, in such cases, the d_addr is forced to 127.0.0.1
					if (stack.local_server_patch)
						try {
							if (InetAddress.getLocalHost().getHostAddress().startsWith("127")) d_addr="127.0.0.1";
							printlog("Local host: "+InetAddress.getLocalHost().getHostAddress(),LoggerLevel.DEBUG);
							printlog("Dest addr: "+d_addr,LoggerLevel.DEBUG);
						}
						catch (Exception e) { e.printStackTrace(); }
						
					reply.send(source_socket,d_addr,d_port);
					printmessagelog(reply);
					printlog("Available addresses: "+available_addresses.size(),LoggerLevel.INFO);
					printlog("Assigned addresses: "+assigned_addresses.size()
								+"\r\n",LoggerLevel.INFO);
				}
				else  {
					printlog("No reply",LoggerLevel.INFO);
					//System.exit(0);
				}
			}
		}
		System.out.println("DHCP server halted");
		running=false;
	}
	
	/** Handles DHCP_DISCOVERY messages. It returns the OFFER message or null if discarded */
	protected DhcpMessage handleDiscover(DhcpMessage message) {
		System.out.println("DEBUG: DhcpServer: handleDiscover()");
		// set the client id
		String cid;
		if (message.hasClientId()) cid=message.getClientId();
		else cid=message.getChaddr();
		
		// add expired addresses to the available_addresses set
		freeExpiredAddresses();
		if (available_addresses.isEmpty() && !assigned_addresses.containsCid(cid)) {
			printlog("No more available addresses: request refused.",LoggerLevel.WARNING);
			return null;
		}
	
		String requested_addr=null;
		if (message.hasRequestedAddress()) message.getRequestedAddress();
		String offered_addr=null;
		String offered_mask=null;
		
		// The offered address should be chosen as follows (RFC2131):
		// o The client's current address as recorded in the client's current
		//   binding, ELSE      
		// o The client's previous address as recorded in the client's (now
		//   expired or released) binding, if that address is in the server's
		//   pool of available addresses and not already allocated, ELSE
		// o The address requested in the 'Requested IP Address' option, if that
		//   address is valid and not already allocated, ELSE     
		// o A new address allocated from the server's pool of available
		//   addresses; the address is selected based on the subnet from which
		//   the message was received (if 'giaddr' is 0) or on the address of
		//   the relay agent that forwarded the message ('giaddr' when not 0).

		// the client's current address as recorded in the client's current binding      
		if (assigned_addresses.containsCid(cid)) {
			offered_addr=assigned_addresses.getAddress(cid);
			offered_mask=(String)masks.get(offered_addr); 
		}
		else
		// the address requested if that address is not already allocated    
		if (requested_addr!=null && available_addresses.contains(requested_addr)) {
			offered_addr=requested_addr;
			offered_mask=(String)masks.get(offered_addr);
		}
		else
		// a new address allocated from the server's pool of available addresses
		if (!available_addresses.isEmpty()) {
			offered_addr=(String)available_addresses.iterator().next();
			offered_mask=(String)masks.get(offered_addr);
		}
		else  {
			// you couldn't arrive here, however..
			return null;
		}

		// choose the lease time
		long lease_time=0;
		if (message.hasLeaseTime()) lease_time=message.getLeaseTime();
		if (lease_time==0 || lease_time>stack.lease_time) lease_time=stack.lease_time;
		
		DhcpMessage reply=msgfactory.createDhcpOffer(message,server_addr,
			offered_addr,offered_mask,lease_time,assigned_router,assigned_dns,domain_name);
		
		// set renewing e rebinding times
		if (message.hasRenewingTime() && message.getRenewingTime()<lease_time)
			reply.setRenewingTime(message.getRenewingTime());        
		if (message.hasRebindingTime() && message.getRenewingTime()<lease_time)
			reply.setRebindingTime(message.getRebindingTime());

		// add NAI and/or SIP server options
		if (nai!=null) reply.setNai(nai);        
		if (sip_server!=null) reply.setSip(sip_server);        
		
		return reply;
	}

	
	/** Handles DHCP_REQUEST messages. It returns the ACK/NACK message or null if discarded */
	protected DhcpMessage handleRequest(DhcpMessage message) {
		printlog("DEBUG: handling request..",LoggerLevel.INFO);
		// set the client id
		String cid;
		if (message.hasClientId()) cid=message.getClientId();
		else cid=message.getChaddr();
		
		// add expired addresses to the available_addresses set
		freeExpiredAddresses();
		if (available_addresses.isEmpty() && !assigned_addresses.containsCid(cid)) {
			printlog("No more available addresses: request refused.",LoggerLevel.WARNING);
			return null;
		}
		
		// if server identifier is present (client is in "selecting" state),
		//    checks if the server address matches       
		if (message.hasServerIdAddress() && !message.getServerIdAddress().equals(stack.server_address)) {
			printlog("Server id mismatching",LoggerLevel.INFO);
			return null;
		}
		// get the requested address (in case of clients in "selecting" or "reboot" state)
		String requested_addr=null;
		if (message.hasRequestedAddress()) requested_addr=message.getRequestedAddress();
		
		// if there is no requested address,
		//    get the ciaddr (in case of clients in "renewing" state)
		if (requested_addr==null) requested_addr=message.getCiaddr();


		// if no ip address and we are acting as MHCP, assign a new address        
		if (requested_addr.equals("0.0.0.0") && stack.mhcp_mode) {
			printlog("MHCP request",LoggerLevel.INFO);
			if (!available_addresses.isEmpty()) {
				requested_addr=(String)available_addresses.iterator().next();
			}
			else {
				printlog("No more available addresses: request refused.",LoggerLevel.WARNING);
				return null;
			}
		}
		
		// if no ip address has been requested simply discard the REQUEST       
		if (requested_addr.equals("0.0.0.0")) {
			printlog("Request address missed",LoggerLevel.INFO);
			return null;
		}

		// get the lease time
		long lease_time=0;
		if (message.hasLeaseTime()) lease_time=message.getLeaseTime();
		if (lease_time==0 || lease_time>stack.lease_time) lease_time=stack.lease_time;

		// if the requested address is still available send the ACK
		freeExpiredAddresses();
		if (available_addresses.contains(requested_addr) || assigned_addresses.containsCid(cid)) {
			String assigned_addr=requested_addr;
			String assigned_mask=(String)masks.get(assigned_addr); 
			
			// update the address db
			if (available_addresses.contains(requested_addr)) {
				assigned_addresses.put(requested_addr,cid,lease_time);
				available_addresses.remove(requested_addr); 
			}        
			else {
				assigned_addresses.renew(requested_addr,lease_time);                           
			}
					  
			// build the ack reply
			DhcpMessage reply=msgfactory.createDhcpAck(message,server_addr,
				assigned_addr,assigned_mask,lease_time,assigned_router,assigned_dns,domain_name);
		  
			// set renewing e rebinding times
			if (message.hasRenewingTime() && message.getRenewingTime()<lease_time)
				reply.setRenewingTime(message.getRenewingTime());        
			if (message.hasRebindingTime() && message.getRenewingTime()<lease_time)
				reply.setRebindingTime(message.getRebindingTime());
							
			// add NAI and/or SIP server options
			if (nai!=null) reply.setNai(nai);        
			if (sip_server!=null) reply.setSip(sip_server);
			
			return reply;
		}
		else {
			DhcpMessage reply=msgfactory.createDhcpNack(message,server_addr);                    
			return reply;
		}
	}

	
	/** Handles DHCP_RELEASE messages. It returns null */
	protected DhcpMessage handleRelease(DhcpMessage message) {
		String cid=message.getChaddr();
		String addr=message.getCiaddr();
			  
		//if (assigned_addresses.containsCid(cid) && assigned_addresses.getAddress(cid).equals(addr))
		if (assigned_addresses.containsAddress(addr)) {
			assigned_addresses.remove(addr);  
			available_addresses.add(addr);
		}
		return null;
	}
	

	/** Handles DHCP_INFORM messages. It returns the ACK message or null if discarded */
	protected DhcpMessage handleInform(DhcpMessage message) {
		
		return msgfactory.createDhcpAck(message,server_addr,null,null,0,assigned_router,assigned_dns,domain_name);
	}


	// **************************** Main ****************************

	public static void main (String [] args) {
		
		String file=DhcpStack.default_config_file;
		String mode=null;
		
		for (int i=0; i<args.length; i++) {
			if (args[i].toLowerCase().startsWith("-f") && args.length>(i+1)) {
				file=args[++i];
				continue;
			}
			if (args[i].toLowerCase().startsWith("-m") && args.length>(i+1)) {
				mode=args[++i];
				continue;
			}
			if (args[i].toLowerCase().startsWith("-h")) {
				System.out.println("usage:\n"
										+"   java DhcpServer [options]\n\n"
										+"options:\n"
										+"   -f  -file  <filename> : configuration file\n"
										+"   -m  -mode  dhcp | adv | dhcpadv | mhcp : server mode\n"
										+"   -h  -help  : this help\n");
				System.exit(0);
			}
		}                  
		// load the server paramethers from configuration file
		DhcpStack mainstack=new DhcpStack(file);
		
		// set the server mode
		if (mode!=null) {
			if (mode.compareToIgnoreCase("dhcp")==0) {
				mainstack.dhcp_mode=true;
				mainstack.mhcp_mode=false;
				mainstack.adv_mode=false;
			}
			else
			if (mode.compareToIgnoreCase("adv")==0) {
				mainstack.dhcp_mode=false;
				mainstack.mhcp_mode=false;
				mainstack.adv_mode=true;
			}
			else
			if (mode.compareToIgnoreCase("dhcpadv")==0) {
				mainstack.dhcp_mode=true;
				mainstack.mhcp_mode=false;
				mainstack.adv_mode=true;
			}
			else
			if (mode.compareToIgnoreCase("mhcp")==0) {
				mainstack.dhcp_mode=false;
				mainstack.mhcp_mode=true;
				mainstack.adv_mode=true;
			}
		}

		DatagramSocket socket = null;
		
		// create the udp socket and start the server
		try {
			//socket=new DatagramSocket(mainstack.server_port,InetAddress.getByName(mainstack.server_address));
			socket=new DatagramSocket(mainstack.server_port);
		}
		catch (Exception e) {
			System.out.println("Error opening UDP socket on port "+mainstack.server_port);
			e.printStackTrace();
			System.exit(0);
		}                
		// start the servers
		if (mainstack.dhcp_mode || mainstack.mhcp_mode) (new DhcpServer(mainstack,socket)).start();
		if (mainstack.mhcp_mode || mainstack.adv_mode) (new DhcpAdv(mainstack,socket)).start();      
	}
	
	// ************************* Static methods *************************

	/** Logs a textual message */
	private void printlog(String str, LoggerLevel level) {
		SystemUtils.getDefaultLogger().log(level,getClass(),str);
	}

	/** Logs a DHCP message */
	private void printmessagelog(DhcpMessage msg) {
		String str=msg.toString();
		printlog(str,LoggerLevel.INFO);
		messagelog.log(LoggerLevel.INFO,null,str);
	}

}
