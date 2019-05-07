package it.unipr.netsec.ipstack.dhcp;


import java.io.InterruptedIOException;
import java.net.DatagramSocket;

import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;


/** Class DhcpClient implements a simple DHCP or MHCP client. */
public class DhcpClient extends Thread implements TimerListener {
	
	/** Message Log (for debugging) */
	Logger messagelog;    

	/** Current DhcpStack */
	DhcpStack stack;

	/** Current MessageFactory */
	MessageFactory msgfactory;

	/** udp socket */
	DatagramSocket socket;
	
	/** client listener */
	DhcpClientListener listener;
	
	/** client internal state */
	String state;
	
	// DHCP client states
	public static final String S_INIT="INIT";
	public static final String S_DISCOVERING="DISCOVERING";
	public static final String S_REQUESTING="REQUESTING";
	public static final String S_BOUND="BOUND";
	public static final String S_RENEWING="RENEWING";
	public static final String S_REBINDING="REBINDING";
	// MHCP new clinet state
	public static final String S_MOVED="MOVED";
	
	// dhcp attributes
	byte[] xid=null;   
	String server=null;
	String addr=null;
	String mask=null;
	String router=null;
	String dns=null;
	String domain_name=null;
	long   lease=0;
	String nai=null;
	String sip_server=null;
		
	/** Retransmission timeout */
	long to_retransmission=4000;
	/** Renewing timeout */
	//long to_renewing=9000;
	/** Rebinding timeout */
	//long to_rebinding=18000;

	/** Retransmission timer */
	Timer T0;
	/** Renewing timer */
	Timer T1;
	/** Rebinding timer */
	Timer T2;
	/** Lease timer */
	Timer T3;


	/** stop flag */
	boolean stop;   
 
	/** running flag */
	boolean running=false;

	/** Constructs the client */
	public DhcpClient(DhcpStack dhcpstack, DatagramSocket udpsocket, DhcpClientListener c_listener) {
		stack=dhcpstack;
		msgfactory=new MessageFactory(stack);
		socket=udpsocket;
		listener=c_listener;
		state=S_INIT;
		messagelog=new LoggerWriter(stack.log_path+"//client-"+stack.client_port+".log",LoggerLevel.INFO); 
  }

	/** Sets the client listener */
	public void setListener(DhcpClientListener c_listener) {
		listener=c_listener;
	}
	
	/** Changes the internal state */
	void changeState(String newstate) {
		state=newstate;
		printlog("Client state: "+state);
	}
	
	/** Whether the internal state is <i>this_state</i> */
	boolean stateIs(String this_state) {
		return state.equals(this_state);
	}   
		
	/** The Thread.run() method */
	public void run() {
		client();
	}

	/** Stops the client */
	public void halt() {
		stop=true;
		printlog("Halting DHCP client...");
	}
		
	/** Whether the server is active */
	public boolean isRunning() {
		return running;
	}

	/** The main client method, invoked by the run() thread */
	public void client() {
		
		stop=false;

		// wait a random time to desynchronize the use of DHCP at startup (RFC 2131)
		try {
			long r=(long)(stack.desync_start_time*stack.rand.nextDouble());
			Thread.sleep(r);
		}
		catch (Exception e) { printlog("Exception fired at startup desynchronization"); }

		// send the appropriate DHCP method (DHCP_DISCOVER or DHCP_REQUEST)
		xid=stack.pickXID(); 
		request();
				
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
			
			// check whether the message is a DHCP reply for the current method or a MHCP ADV
			if (message.isReply() && (message.stringXid().equals(Mangle.bytesToHexString(xid)) || message.isDhcpAdv())) {
				
				if (message.isDhcpOffer()) handleOffer(message); 
				if (message.isDhcpAck()) handleAck(message);                      
				if (message.isDhcpNack()) handleNack(message); 
				if (message.isDhcpAdv()) handleAdv(message); 
			}                    
		}
		System.out.println("DHCP client halted");
		running=false;
	}

	/** Request a new lease.
	  * It sends a DHCP DISCOVER or REQUEST message,
	  * according to the current state and client mode (dhcp or mhcp) */
	public void request() {
		if (stateIs(S_INIT)) {
			changeState(S_DISCOVERING);
			if (listener!=null) listener.onDiscovering(this);
			sendDhcpDiscover();          
		}
		else
		if (stateIs(S_DISCOVERING)) {
			sendDhcpDiscover();     
		}
		else
		if (stateIs(S_REQUESTING) || stateIs(S_RENEWING) || stateIs(S_REBINDING) || stateIs(S_MOVED)) {
			sendDhcpRequest();     
		}
		else
		return;
		
		T0=new Timer(to_retransmission,0,this);
		T0.start();    
	}

	/** Release the lease  */
	public void release() {
		
	}

	/** Send a DHCP discover */
	protected void sendDhcpDiscover() {
		DhcpMessage req=null;
		String d_addr=stack.broadcast_address;
		int d_port=stack.server_port;
		
		if (stateIs(S_DISCOVERING)) {
			xid=stack.pickXID();
			req=msgfactory.createDhcpDiscover(xid,null,0);
		}
		
		if (req!=null) {
			req.send(socket,d_addr,d_port);
			printmessagelog(req);
		}
	}


	/** Send a DHCP request */
	protected void sendDhcpRequest() {
		DhcpMessage req=null;
		String d_addr=stack.broadcast_address;
		int d_port=stack.server_port;
		
		if (stateIs(S_REQUESTING)) {
			req=msgfactory.createDhcpRequest(xid,null,addr,0,server);
		}
		else
		if (stateIs(S_RENEWING)) {
			d_addr=server;
			req=msgfactory.createDhcpRequest(xid,addr,addr,lease,null);
		}
		else
		if (stateIs(S_REBINDING)) {
			req=msgfactory.createDhcpRequest(xid,addr,addr,lease,null);
		}
		else
		if (stateIs(S_MOVED)) {
			req=msgfactory.createMhcpRequest(xid,server,nai);
		}

		if (req!=null) {
			req.send(socket,d_addr,d_port);
			printmessagelog(req);
		}
	}

	
	/** Handles DHCP_OFFER messages */
	protected void handleOffer(DhcpMessage msg) {
		if (stateIs(S_DISCOVERING)) {
			String offered_addr=msg.getYiaddr();
			String offered_server=msg.getServerIdAddress();
			if (addr!=null && (!addr.equals(offered_addr) || (server!=null && !server.equals(offered_server))))
				return;
			//else
			addr=offered_addr;
			server=offered_server;
			changeState(S_REQUESTING);
			if (listener!=null) listener.onRequesting(this);
			request();
		}
	}  

	/** Handles DHCP_ACK messages */
	protected void handleAck(DhcpMessage msg) {
		if (stateIs(S_REQUESTING) || stateIs(S_RENEWING) || stateIs(S_REBINDING) || stateIs(S_MOVED)) {
			addr=msg.getYiaddr();
			server=msg.getServerIdAddress();
			if (msg.hasMask()) mask=msg.getMask();
			if (msg.hasRouter()) router=msg.getRouter();
			if (msg.hasDns()) dns=msg.getDns();
			if (msg.hasDomainName()) domain_name=msg.getDomainName();
			if (msg.hasLeaseTime()) lease=msg.getLeaseTime();
			if (msg.hasNai()) nai=msg.getNai();
			if (msg.hasSip()) sip_server=msg.getSip();
			changeState(S_BOUND);
			if (listener!=null) listener.onBound(this,msg);

			// halt all timers.. (not strictly necessary)
			//if (T0!=null) T0.halt();
			//if (T1!=null) T1.halt();
			//if (T2!=null) T2.halt();
			//if (T3!=null) T3.halt();
			T1=new Timer(lease/2,0,this);
			T2=new Timer(lease*3/4,0,this);
			T3=new Timer(lease,0,this);
			T1.start();
			T2.start();
			T3.start();         
		}
	}  

	/** Handles DHCP_NACK messages */
	protected void handleNack(DhcpMessage msg) {
		if (stateIs(S_RENEWING)) {
			changeState(S_REBINDING);
			if (listener!=null) listener.onRebinding(this);
			xid=stack.pickXID();
			request();
		}
		if (stateIs(S_REBINDING)) {
			changeState(S_DISCOVERING);
			if (listener!=null) listener.onDiscovering(this);
			xid=stack.pickXID();
			request();
		}
	}  

	/** Handles DHCP_ADV messages */
	protected void handleAdv(DhcpMessage msg) {
		String offered_nai=msg.getNai();
		if (nai==null || !nai.equals(offered_nai)) {
			nai=offered_nai;
			server=msg.getServerIdAddress();
			// release the previous address (?)
			//..
			
			if (stack.mhcp_mode) {
				changeState(S_MOVED);
				if (listener!=null) listener.onMoved(this,nai);
				xid=stack.pickXID();
				request();
			}
			else
			if (stack.adv_mode)          {
				changeState(S_DISCOVERING);
				if (listener!=null) listener.onDiscovering(this);
				xid=stack.pickXID();
				request();
			}
		}
	}  


	// *********** Callback functions from TimerListener ************
	
	//** TimerListener callback-function */
	public void onTimeout(Timer t) {
		if (t.equals(T0)) {
			if (stateIs(S_REQUESTING)) {
				changeState(S_DISCOVERING);
				xid=stack.pickXID();
			}
			request();
		}
		else
		if (t.equals(T1) && stateIs(S_BOUND)) {
			changeState(S_RENEWING);
			if (listener!=null) listener.onRenewing(this);
			xid=stack.pickXID(); 
			request();
		}
		else
		if (t.equals(T2) && stateIs(S_RENEWING)) {
			changeState(S_REBINDING);
			if (listener!=null) listener.onRebinding(this);
			xid=stack.pickXID(); 
			request();
		}
		else
		if (t.equals(T3)) { // probably we are in S_REBINDING..
			changeState(S_DISCOVERING);
			if (listener!=null) listener.onDiscovering(this);
			xid=stack.pickXID(); 
			request();
		}
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
										+"   java DhcpClient [options]\n\n"
										+"options:\n"
										+"   -f  -file  <filename> : configuration file\n"
										+"   -m  -mode  dhcp | dhcpadv | mhcp : client mode\n"
										+"   -h  -help  : this help\n");
				System.exit(0);
			}
		}                  

		// load the client paramethers from configuration file
		DhcpStack mainstack=new DhcpStack(file);
		
		// set the client mode
		if (mode!=null) {
			if (mode.compareToIgnoreCase("dhcp")==0) {
				mainstack.dhcp_mode=true;
				mainstack.mhcp_mode=false;
				mainstack.adv_mode=false;
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
		
		// create the udp socket and start the client
		try {
			socket=new DatagramSocket(mainstack.client_port);
		}
		catch (Exception e) {
			System.out.println("Error opening UDP socket on port "+mainstack.client_port);
			e.printStackTrace();
			System.exit(0);
		}                
		// start the client
		DhcpClient dhcp_c=new DhcpClient(mainstack,socket,null);
		dhcp_c.start();
	}
	
	// ************************* Static methods *************************

	/** Prints a log */
	private void printlog(String str) {
		SystemUtils.getDefaultLogger().log(LoggerLevel.INFO,getClass(),str);
	}

	/** Prints a messagelog */
	private void printmessagelog(DhcpMessage msg) {
		String str=msg.toString();
		printlog(str);
		messagelog.log(LoggerLevel.INFO,null,str);
	}
}
