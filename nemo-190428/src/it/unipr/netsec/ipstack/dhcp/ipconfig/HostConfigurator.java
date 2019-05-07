package it.unipr.netsec.ipstack.dhcp.ipconfig;


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.dhcp.DhcpStack;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;


/** HostConfigurator is the basic object used to configure the ip stack of the host OS.
  * The abstract method configure() must be extended in order to obtain a platform dependent configuration.
  */
public abstract class HostConfigurator {
	
	protected DhcpStack stack;
	
	protected String address;
	protected String mask;
	protected String router;
	protected long time;
	protected String domain_name;
	protected String dns_server;
	protected String nai;
	protected String sip_server;
	//String host_name;
	//String smtp_server;
	//String http_server;
	
	/** Costructs a new generic HostConfigurator */
	public HostConfigurator(DhcpStack dhcpstack, String my_address, String my_mask, String my_router, long lease_time) {
		stack=dhcpstack;
		address=my_address;
		mask=my_mask;
		router=my_router;
		time=lease_time;
	}

	/** Sets a new domain name */
	public void setDomainName(String my_domain_name) { domain_name=my_domain_name; }
	/** Sets a new NAI */
	public void setNai(String my_nai) { nai=my_nai; }
	/** Sets a new default DNS server */
	public void setDns(String my_dns_server) { dns_server=my_dns_server; }
	/** Sets a new default SIP server */
	public void setSip(String my_sip_server) { sip_server=my_sip_server; }
	//public void setHostName(String my_host_name) { host_name=my_host_name; }
	//public void setSmtp(String my_smtp_server) { smtp_server=my_smtp_server; }
	//public void setHttp(String my_http_server) { http_server=my_http_server; }

	
	/** Configure the local Host with the new IP configuration */
	public abstract void configure();
 
	
	/** Configures the SIP stack with the default SIP server */
	public void configureSip() {
		if (sip_server==null) return;
		
	SystemUtils.getDefaultLogger().log(LoggerLevel.INFO,getClass(),"configure sip outbound server: "+sip_server);
		try {
			BufferedWriter out=new BufferedWriter(new FileWriter(stack.sip_outbound_file));
			out.write(sip_server);
			out.close();
		}
		catch (IOException e) {
			System.err.println("WARNING: error trying to write on file \""+stack.sip_outbound_file+"\"");
			e.printStackTrace();
		}

		try {
			byte[] buf=sip_server.getBytes();
			DatagramPacket packet = new DatagramPacket(buf,buf.length);
			packet.setAddress(InetAddress.getByName("127.0.0.1"));
			packet.setPort(stack.sip_outbound_port);
			DatagramSocket socket=new DatagramSocket();
			socket.send(packet);   
			socket.close();
		} catch (Exception e) {
			System.err.println("WARNING: error trying to send the sip_outbound token to local port "+stack.sip_outbound_port);
			e.printStackTrace();
		}

	}
	
}
