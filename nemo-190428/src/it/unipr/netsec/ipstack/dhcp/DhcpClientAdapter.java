package it.unipr.netsec.ipstack.dhcp;


import java.net.DatagramSocket;

import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.dhcp.ipconfig.HostConfigurator;


/** Class DhcpClientAdapter extends DhcpClient implementing DhcpClientListener.
  */
public abstract class DhcpClientAdapter extends DhcpClient implements DhcpClientListener {
	
	String current_address="";
	
	/** Constructs the client */
	public DhcpClientAdapter(DhcpStack dhcpstack, DatagramSocket udpsocket) {
		super(dhcpstack,udpsocket,null);
		setListener(this);
	}

	// ********* Callback functions from DhcpClientListener *********
	
	/** When the client state moves to DISCOVERING state */
	public void onDiscovering(DhcpClient c) {
		
	}   

	/** When the client state moves to REQUESTING state */
	public void onRequesting(DhcpClient c) {
		
	} 

	/** When the client state moves to RENEWING state */
	public void onRenewing(DhcpClient c) {
		
	} 

	/** When the client state moves to BOUND state */
	public void onBound(DhcpClient c, DhcpMessage ack) {
		String yiaddr=ack.getYiaddr();
		if (current_address.equals(yiaddr)) return;
		// if you are here, the address is changed
		current_address=yiaddr;
		HostConfigurator configurator=getConfigurator();
		
		if (configurator!=null) {
			configurator.setDns(ack.getDns());
			configurator.setDomainName(ack.getDomainName());
			configurator.setNai(ack.getNai());
			configurator.setSip(ack.getSip());
			
			configurator.configure();
			configurator.configureSip();
		}
	}
	
	/** Gets a OS-depended host configurator.
	 * @return the host configurator */
	abstract protected HostConfigurator getConfigurator(); /* {
		if (stack.system.compareToIgnoreCase("win")==0) {
			configurator=new WindowsConfigurator(stack,yiaddr,ack.getMask(),ack.getRouter(),ack.getLeaseTime());
		}
		else
		if (stack.system.compareToIgnoreCase("macos")==0) {
			configurator=new MacOSConfigurator(stack,yiaddr,ack.getMask(),ack.getRouter(),ack.getLeaseTime());
		}
		else
		if (stack.system.compareToIgnoreCase("linux")==0) {
			configurator=new LinuxConfigurator(stack,yiaddr,ack.getMask(),ack.getRouter(),ack.getLeaseTime());
		}
	}*/
	

	/** When the client state moves to REBINDING state */
	public void onRebinding(DhcpClient c) {
		
	} 
	
	/** When the client state moves to MOVED state,
	  * i.e. the client has moved into a new network */
	public void onMoved(DhcpClient c, String nai) {
		
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
										+"   java DhcpClientAdapter [options]\n\n"
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
		// TODO
		//DhcpClientAdapter dhcp_c=new DhcpClientAdapter(mainstack,socket);
		//dhcp_c.start();
	}
	
}
