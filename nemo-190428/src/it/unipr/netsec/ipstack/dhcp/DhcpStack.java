package it.unipr.netsec.ipstack.dhcp;


import org.zoolu.util.Parser;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;

import java.util.Vector;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.Random;


/** Default dhcp settings and static methods for loading, saving,
  * and managing dhcp stuffs.
  * <p>
  * Static attributes specify the configuration file, the default log output,
  * ip_address and port numbers, timeouts, client and server specific configurations.
  * <p>
  * Static methods includes method for loading DhcpStack parameters
  * and for generating DHCP client XID.
  */
public class DhcpStack {
	
	/** The default configuration file */
	public final static String default_config_file="dhcp.cfg";

	/** The current configuration file */
	public String config_file=default_config_file;
 
	// *********************** software release ***********************

	/** Release */
	public final static String this_release="Dhcpd 1.3";
	/** Authors */
	public final static String author="Luca Veltri - University of Parma (Italy)";


	// ************************ dhcp constants *************************   
	/** Magic cookie. The 4-bytes-cookie that starts the option field */ 
	public static byte[] magic_cookie={(byte)99,(byte)130,(byte)83,(byte)99};
	/** Magic cookie string */
	public final static String magic_cookie_hex="63825363";
	/** Magic cookie int */
	public final static int magic_cookie_int=0x63825363;

	/** Dhcp NAI option code */
	public final static int nai_option=131;
	/** Dhcp SIP option code */
	public final static int sip_option=120;


	// ************************ debug and logs ************************

	/** Log level. Only logs with a level less or equal to this are printed */
	public int debug_level=3;
	/** Log file. String "standard" identifies the standard output */
	public String log_file="standard";
	/** Path to be added to any log file names, i.e. the root log directory.
	  * The default value is ".", that is the current directory. */
	public String log_path=".";

	 
	// ******************** general configurations ********************
	
	/** Logo file */
	//public static String logo_file="logo.gif";
	
	/** Dhcp server port (udp) */
	public int server_port=67;
	/** Dhcp client port (udp) */
	public int client_port=68;     

	/** Dhcp scope. Set 127.0.0.1 for local or 255.255.255.255 for limited broadcast */ 
	public String broadcast_address="255.255.255.255";  
	/** Whether acting as dhcp server (yes/no) */
	public boolean dhcp_mode=true;
	/** Whether acting as mhcp server (yes/no) */
	public boolean mhcp_mode=false;
	/** Whether sending mhcp advertisement (yes/no) */
	public boolean adv_mode=false;


	// ******************** server configurations *********************

	/** Dhcp server address */
	public String server_address="127.0.0.1";

	/** Send packets through a different socket bound to a specific interface.
	  * This option can be useful to force broadcast packets to be sent through
	  * a specific interface, in OSs that do not forward broadcast packet to all interfaces.
	  * VERY IMPORTANT: Some DHCP clients do not recognize DHCP message received with a
	  * non-standard source port. (values: yes/no) */
	public boolean source_socket_patch=false;

	/** Send broadcast packet to 127.0.0.1 when no ip address is in use for the local host.
	  * This option can be used when the dhcp server run on a dhcp client host. (values: yes/no) */
	public boolean local_server_patch=false;

	/** Dhcp available addresses (as strings in the form of address/mask) */
	public String[] available_addresses=null; //example: {"192.168.0.71/255.255.255.0"};
	/** Router address */
	public String router=null;      //example: "192.168.0.1";
	/** DNS server address */
	public String dns=null;         //example: "193.205.242.5";
	/** Domain name */
	public String domain_name=null; //example: domain_name="home.net";
	/** Dhcp NAI */
	public String nai=null;         //example: "nai=test@test.net";
	/** SIP proxy server (P-CSCF) */
	public String sip_server=null;  //example: "sip_server=sip.home.net";
	
	
	/** Lease time [millisecs] */
	public long lease_time=3600*24;
	/** Renewing time [millisecs] */
	public long renewing_time=3600*12;
	/** Rebinding time [millisecs] */
	public long rebinding_time=3600*21;
	/** Dhcp advertisement period [millisecs] */
	public long adv_time=5000;


	// ******************** client configurations *********************

	/** Operative System (linux | win98 | winNT | win2000 | winXP) */
	public String system="unknown";

	/** OS language, required for win2000 (ita | eng) */
	public String language="eng";

	/** Client hardware type */
	public byte htype=1;
	/** Client hardware length */
	public byte hlen=6;
	/** Client hardware address */
	public String chaddr="00:00:00:00:00:00";  
	/** Client identifier */
	public String client_id=null;
	/** Class identifier */ 
	public String class_id=null;
	/** Desynchronizing startup time [millisecs] */
	public long desync_start_time=1000;
	
	/** SIP outbound server output file */
	public String sip_outbound_file="sip_outbound.cfg";
	/** SIP outbound server output udp local port */
	public int sip_outbound_port=1433;


	// ********************* friend attributesons *********************

	/** Random base generator */
	static Random rand = new Random();             


	// ************************ public methods ************************

	/** Costructs a new DhcpStack with configurations from the default file (if present) */
	public DhcpStack() {
		load(config_file);
	}

	/** Costructs a new DhcpStack with configurations from file <i>file</i> */
	public DhcpStack(String file) {
		config_file=file;
		load(config_file);
	}

	/** Loads settings from the default configuration file */
	public void load() {
		
		load(config_file);
	}
		 
	/** Loads the settings from the configuration file <i>config_file</i>,
	  * and initialize the default (static) Log */
	public void load(String file) {
		
		BufferedReader in=null;
		try { in = new BufferedReader(new FileReader(file)); }
	      catch (FileNotFoundException e)
  		   {  System.err.println("WARNING: configuration file \""+file+"\" not found: using default values");
				//System.exit(0);
				return;
			}
			config_file=file;
		
		// temp auxiliar variables
		Vector address_list=new Vector();
		String current_mask="255.255.255.0";
		String first_addr="1.0.0.1";
		String last_addr;
			
		while (true) {
			String line=null;
			try { line=in.readLine(); } catch (Exception e) { e.printStackTrace(); System.exit(0); }
			if (line==null) break;
		
			Parser par=new Parser(line);
		
			if (line.startsWith("#")) continue;
			// ************************ debug and logs ************************
			if (line.startsWith("debug_level"))    { debug_level=par.goTo('=').skipChar().getInt(); continue; }
			if (line.startsWith("log_file"))       { log_file=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("log_path"))       { log_path=par.goTo('=').skipChar().getString(); continue; }

			// ******************** general configurations ********************
			if (line.startsWith("server_port"))   { server_port=par.goTo('=').skipChar().getInt(); continue; }
			if (line.startsWith("client_port"))   { client_port=par.goTo('=').skipChar().getInt(); continue; }

			if (line.startsWith("broadcast_address")) { broadcast_address=par.goTo('=').skipChar().getString(); continue;}
			if (line.startsWith("dhcp_mode"))     { dhcp_mode=par.goTo('=').skipChar().getString().toLowerCase().startsWith("y"); continue; }
			if (line.startsWith("mhcp_mode"))     { mhcp_mode=par.goTo('=').skipChar().getString().toLowerCase().startsWith("y"); continue; }
			if (line.startsWith("adv_mode"))      { adv_mode=par.goTo('=').skipChar().getString().toLowerCase().startsWith("y"); continue; }

			// ********************* server configurations ********************
			if (line.startsWith("server_address")){ server_address=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("source_socket_patch")) { source_socket_patch=par.goTo('=').skipChar().getString().toLowerCase().startsWith("y"); continue; }
			if (line.startsWith("local_server_patch")) { local_server_patch=par.goTo('=').skipChar().getString().toLowerCase().startsWith("y"); continue; }
			if (line.startsWith("router"))        { router=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("dns"))           { dns=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("domain_name"))   { domain_name=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("nai"))           { nai=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("sip_server"))    { sip_server=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("lease_time"))    { lease_time=par.goTo('=').skipChar().getInt(); continue; }
			if (line.startsWith("renewing_time")) { renewing_time=par.goTo('=').skipChar().getInt(); continue; }
			if (line.startsWith("rebinding_time")){ rebinding_time=par.goTo('=').skipChar().getInt(); continue; }
			if (line.startsWith("adv_time"))      { adv_time=(long)par.goTo('=').skipChar().getInt(); continue;}         

			// server address loading
			if (line.startsWith("mask"))          { current_mask=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("first_addr"))    { first_addr=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("last_addr")) {
				last_addr=par.goTo('=').skipChar().getString();
				int indexofhostid=first_addr.lastIndexOf(".")+1;
				String netid=first_addr.substring(0,indexofhostid);
				if (!last_addr.substring(0,indexofhostid).equals(netid))
					System.err.println("Error reading address set {"+first_addr+"-"+last_addr+"}: first and last addresses may differ only on last byte; address set discarded."); 
				else {
					int hostid=Integer.parseInt(first_addr.substring(indexofhostid));
					int last=Integer.parseInt(last_addr.substring(indexofhostid));
					for (;hostid<=last;hostid++) {
						String complete_addr=(netid+String.valueOf(hostid)+"/"+current_mask);
						address_list.addElement(complete_addr);
					}   
				}
				continue;
			}        

			// ********************* client configurations ********************
			if (line.startsWith("system"))        { system=par.goTo('=').skipChar().getRemainingString(); }
			if (line.startsWith("language"))      { language=par.goTo('=').skipChar().getRemainingString(); }
			if (line.startsWith("htype"))         { htype=(byte)par.goTo('=').skipChar().getInt(); continue;}
			if (line.startsWith("hlen"))		     { hlen=(byte)par.goTo('=').skipChar().getInt(); continue; }
			if (line.startsWith("chaddr"))        { par.goTo('=').skipChar().skipChar().getString(); continue; }
			if (line.startsWith("client_id"))     { client_id=par.goTo('=').skipChar().getString(); continue; }
			if (line.startsWith("class_id"))      { class_id=par.goTo('=').skipChar().getString(); continue;}
			if (line.startsWith("desync_start_time")) { desync_start_time=(long)par.goTo('=').skipChar().getInt(); continue;}         
			if (line.startsWith("sip_outbound_file")) { sip_outbound_file=par.goTo('=').skipChar().getRemainingString(); }
			if (line.startsWith("sip_outbound_port")) { sip_outbound_port=(byte)par.goTo('=').skipChar().getInt(); continue; }
		}
		
		if (log_file.equals("standard")) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
		else SystemUtils.setDefaultLogger(new LoggerWriter(log_path+"//"+log_file,LoggerLevel.DEBUG));

		// load available_addresses array
		available_addresses=new String[address_list.size()];
		printlog("Available addresses: "+available_addresses.length);
		for (int i=0;i<available_addresses.length;i++) available_addresses[i]=(String)address_list.elementAt(i);
		
		printlog("Settings loaded");
		
		// do some adjustements
		//..
	}

 
	/** Creates a random XID (transaction ID) */
	public static byte[] pickXID() {
		byte[] xid=new byte[4];
		for (int i=0; i<4; i++) {
			xid[i]=(byte)(rand.nextInt(256));
		}
		return xid;
	}

	
	// ************************ private methods ************************

	private void printlog(String str) {
		printlog(str,LoggerLevel.INFO); 
	}
	
	private void printlog(String str, LoggerLevel level) {
		SystemUtils.getDefaultLogger().log(level,getClass(),str);
	}
}
