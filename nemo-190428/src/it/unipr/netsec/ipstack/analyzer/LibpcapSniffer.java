package it.unipr.netsec.ipstack.analyzer;


import java.io.IOException;

import it.unipr.netsec.ipstack.ip4.Ip4EthInterface;
import it.unipr.netsec.ipstack.ip6.Ip6EthInterface;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.rawsocket.ethernet.RawEthInterface;


/** Libpcap-compatible sniffer.
 * Attached to a network interface, it captures all packets and writes them to a file using standard libpcap format.
 */
public class LibpcapSniffer {

	/** Whether to skip SSH packets (TCP port 22) */
	boolean no_ssh=false;
	
	/** The libpcap trace */
	LibpcapTrace trace;

	
	/** Create a new sniffer.
	 * @param ni the network interface
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	public LibpcapSniffer(NetInterface ni, String file_name) throws IOException {
		int link_type=
			ni instanceof RawEthInterface? LibpcapHeader.LINKTYPE_ETHERNET :
			ni instanceof Ip4EthInterface? LibpcapHeader.LINKTYPE_IPV4 :
			ni instanceof Ip6EthInterface? LibpcapHeader.LINKTYPE_IPV6 : -1;
		if (link_type>=0) init(ni,link_type,file_name);
		else throw new RuntimeException("interface type '"+ni.getClass().getSimpleName()+"' not supported for sniffing."); 
	}

	
	/** Create a new sniffer.
	 * @param ni the network interface
	 * @param type the interface type
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	public LibpcapSniffer(NetInterface ni, int type, String file_name) throws IOException {
		init(ni,type,file_name);
	}

	
	/** Inits the sniffer.
	 * @param ni the network interface
	 * @param type the interface type
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	private void init(NetInterface ni, int type, String file_name) throws IOException {
		trace=new LibpcapTrace(type,file_name);
		NetInterfaceListener listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				if (!no_ssh || ProtocolAnalyzer.exploreInner(pkt).toString().indexOf(":22 ")<0) trace.add(pkt);
			}
		};
		if (ni instanceof RawEthInterface) ((RawEthInterface)ni).addPromiscuousListener(listener);
		else ni.addListener(listener);
	}

	
	/** Whether to skip SSH packets (TCP port 22).
	 * @param no_ssh <i>true</i> to skip SSH packets (TCP port 22) */
	public void skipSSH(boolean no_ssh) {
		this.no_ssh=no_ssh;
	}
	
	
	/** Stops capturing and closes the file. */
	public void close() {
		trace.close();
	}
	
}
