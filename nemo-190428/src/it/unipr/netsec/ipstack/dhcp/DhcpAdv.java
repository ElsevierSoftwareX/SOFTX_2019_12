package it.unipr.netsec.ipstack.dhcp;


import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import java.net.DatagramSocket;
import java.net.InetAddress;


/** DhcpAdv periodically sends MHCP advertisement messages
  */
public class DhcpAdv extends Thread {
	
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

	// mhcp attributes   
	String server_addr;
	String nai;

	/** stop flag */
	boolean stop;

	/** running flag */
	boolean running=false;

	/** adv timeout */
	long timeout;
		
	public DhcpAdv (DhcpStack dhcpstack, DatagramSocket udpsocket) {
		stack=dhcpstack;
		msgfactory=new MessageFactory(stack);
		socket=udpsocket;
		source_socket=socket;
		if (stack.source_socket_patch) {
			try { source_socket=new DatagramSocket(stack.server_port+20,InetAddress.getByName(stack.server_address)); } catch (Exception e) { e.printStackTrace(); } 
		}
		server_addr=stack.server_address;
		nai=stack.nai;
		timeout=stack.adv_time;
		messagelog=new LoggerWriter(stack.log_path+"//server-adv-"+stack.server_port+".log",LoggerLevel.INFO); 
	}
	
	/** Whether the server is active */
	public boolean isRunning() {
		return running;
	}

	/** The Thread.run() method */
	public void run() {
		server();
	}
	
	/** Stops the server */
	public void halt() {
		stop=true;
	 SystemUtils.getDefaultLogger().log(LoggerLevel.INFO,getClass(),"Halting MHCP_ADV server...");
	}
	
	/** The main method, invoked by the run() thread */
	public void server() {
		
		DhcpMessage adv=msgfactory.createDhcpAdv(server_addr,nai);
				
		stop=false;
		running=true;
		try {
			while (!stop) {
				// sends the advertisement message and sleeps 
				adv.send(source_socket,stack.broadcast_address,stack.client_port);
				printmessagelog(adv);
				Thread.sleep(timeout);
			}
			socket.close();
		}
		catch (Exception e) { e.printStackTrace(); } 
		System.out.println("ADV server halted");
		running=false;
	}

	// ************************* Static methods *************************

	/** Logs a textual message */
	private void printlog(String str) {
		SystemUtils.getDefaultLogger().log(LoggerLevel.INFO,getClass(),str);
	}

	/** Logs a DHCP message */
	private void printmessagelog(DhcpMessage msg) {
		String str=msg.toString();
		printlog(str);
		messagelog.log(LoggerLevel.INFO,null,str);
	}
		
}
