/*
 * Copyright 2018 NetSec Lab - University of Parma
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author(s):
 * Luca Veltri (luca.veltri@unipr.it)
 */

package test;


import it.unipr.netsec.nemo.ip.Ip4Host;
import it.unipr.netsec.nemo.ip.Ip4Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.DataLink;
import it.unipr.netsec.nemo.link.DataLinkInterface;
import it.unipr.netsec.nemo.link.PromiscuousLinkInterface;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.graph.Graph;
import it.unipr.netsec.nemo.routing.sdn.SdnRouting;
import it.unipr.netsec.ipstack.analyzer.ProtocolAnalyzer;
import it.unipr.netsec.ipstack.analyzer.Sniffer;
import it.unipr.netsec.ipstack.analyzer.SnifferListener;
import it.unipr.netsec.ipstack.icmp4.PingClient;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4EthInterface;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.udp.DatagramSocket;
import it.unipr.netsec.ipstack.udp.UdpLayer;
import it.unipr.netsec.ipstack.util.IpAddressUtils;
import it.unipr.netsec.rawsocket.ethernet.RawEthInterface;
import it.unipr.netsec.simulator.scheduler.VirtualClock;
import it.unipr.netsec.tuntap.Ip4TunInterface;
import it.unipr.netsec.tuntap.Ip4TuntapInterface;
import it.unipr.netsec.tuntap.TapInterface;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.Clock;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;


/** Routing in IPv4 network with Manhattan or linear topology.
 * the IPv4 is attached to an external network that can be a virtual or physical network.
 * In the latter case the network is attached to one of the available Ethernet physical interfaces.
 * <p>
 * In case of virtual external network, a PING client is automatically run on a virtual host attached to the external network.
 * <p>
 * In case of physical external network, any node attached to the external network can be used to ping internal nodes.
 * In this case the routing table of the external node must be properly configured to route packets directed to the internal network
 * through the gateway router (virtual node) attached to both the internal and external networks.
 */
public class IPv4HybridRoutingTest {

	/** DataLink bit rate */
	//static long LINK_BIT_RATE=1000000L;
	static long LINK_BIT_RATE=10000000L;
	//static long LINK_BIT_RATE=0;
	
	
	static SnifferListener sniffer_listener=new SnifferListener() {
		@Override
		public void onPacket(Sniffer sniffer, NetInterface ni, Packet pkt) {
			System.out.println(ProtocolAnalyzer.packetDump(pkt,ni.getName()));
		}	
	};

	
	/** Test with one router and one host.
	 * The router has two interfaces respectively attached to the external Ethernet network and to an internal virtual link.
	 * The host is attached to the virtual link.
	 * <p>
	 * <p><center>
	 * (Ethernet)---R1---(link1)---H1
	 * </center><p> 
	 * @param tcpdump whether running tcpdump */
	private static void testHybridRoute(boolean tcpdump) {
		try {
			// addresses
			Ip4AddressPrefix r1_1_1=new Ip4AddressPrefix("192.168.56.51/24");
			Ip4AddressPrefix r1_1_2=new Ip4AddressPrefix("192.168.56.21/24");
			Ip4AddressPrefix r1_2=new Ip4AddressPrefix("10.1.0.1/24");
			Ip4AddressPrefix h1=new Ip4AddressPrefix("10.1.0.2/24");
			Ip4Address tcpdump_addr=new Ip4Address("10.1.0.254");
		
			// internal network
			DataLink link1=new DataLink(LINK_BIT_RATE);
						
			// R1
			NetInterface r1_eth0=new Ip4EthInterface(new RawEthInterface("eth0"),new Ip4AddressPrefix(r1_1_1,24));
			r1_eth0.addAddress(r1_1_2);
			NetInterface r1_eth1=new DataLinkInterface(link1,r1_2);
			Ip4Layer router1=new Ip4Layer(new NetInterface[]{r1_eth0, r1_eth1});
			router1.setForwarding(true);
			
			// H1 network layer
			NetInterface h1_eth0=new DataLinkInterface(link1,h1);
			Ip4Layer host1=new Ip4Layer(new NetInterface[]{h1_eth0});
			//host1.getRoutingTable().add(new Route(new Ip4Prefix("0.0.0.0/0"),r1_2,h1_eth0));
			host1.getRoutingTable().setDefaultRoute(new Route(null,r1_2,h1_eth0));
			/*host1.setListener(Ip4Packet.IPPROTO_ICMP,new Ip4ProviderListener() {
				@Override
				public void onReceivedPacket(Ip4Provider ip_provider, Ip4Packet ip_pkt) {
					System.out.println("H1: received IP packet: length: "+ip_pkt.getPacketLength());
				}		
			});*/
					
			System.out.println("H1-RT:");
			System.out.println(host1.getRoutingTable().toString());
			System.out.println("R1-RT:");
			System.out.println(router1.getRoutingTable().toString());
			
			if (tcpdump) {
				new Sniffer(new NetInterface[]{ new RawEthInterface("eth0"), new PromiscuousLinkInterface(link1,tcpdump_addr) },sniffer_listener);
			}
			
			// H1 transport layer
			DatagramSocket udp_socket=new DatagramSocket(new UdpLayer(host1),5555);
			DatagramPacket datagram_packet=new DatagramPacket(new byte[1024],0);
			while (true) {
				udp_socket.receive(datagram_packet);
				System.out.println("UDP ECHO: received data: "+ByteUtils.asHex(datagram_packet.getData(),datagram_packet.getOffset(),datagram_packet.getLength()));
				datagram_packet.setPort(5555);
				System.out.println("UDP ECHO: reply to: "+datagram_packet.getAddress().getHostAddress().toString());			
				udp_socket.send(datagram_packet);
			}
			//udp_socket.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	
	/** IPv4 linear topology with N routers, and one host.
	 * The first router G0 may be a gateway connected to external network.
	 * <p>
	 * <p><center>
	 * (Ethernet)-G0-(link0)-R1-(link1)-R2-(link2)-..-(linkN-2)-R[N-1]-(linkN-1)-H1
	 * </center><p> 
	 * @param n the number of routers, including the access gateway
	 * @param r0_ext_if external interface of G0 (or null in case of virtual interface)
	 * @param r0_ext_addr_prefix IPv4 address and prefix length on the external interface of G0
	 * @param algo shortest-path algorithm
	 * @param udp_echo whether running a UDP echo server on H2
	 * @param tcpdump whether running tcpdump
	 * @param ping_count number of ping requests
	 * @param ping_time time between ping requests */
	/*private static void testLinearNetwork(int n, String r0_ext_if, Ip4AddressPrefix r0_ext_addr_prefix, ShortestPathAlgorithm algo, boolean udp_echo, boolean tcpdump, int ping_count, long ping_time) {
		System.out.println("Network topology: "+n+" linear");
		try {
			// create all links
			IpLink[] links=new IpLink[n];
			for (int i=0; i<n; i++) links[i]=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10."+i+".0.0/16"));
			
			// array of routers
			Ip4Router[] routers=new Ip4Router[n];	
			
			// dynamic routing
			SdnRouting routing=new SdnRouting(algo);

			// create the first router (R0=G0)
			DataLink ext_link=null;
			System.out.println("R00 external interface address: "+r0_ext_addr_prefix);
			if (r0_ext_if!=null) {
				boolean is_tuntap=r0_ext_if.startsWith("tun") || r0_ext_if.startsWith("tap") || r0_ext_if.startsWith("utun");
				NetInterface r0_eth0=is_tuntap? new Ip4TuntapInterface(r0_ext_if, r0_ext_addr_prefix) : new Ip4EthInterface(new RawEthInterface(r0_ext_if),r0_ext_addr_prefix);
				NetInterface r0_eth1=new DataLinkInterface(links[0],links[0].nextAddressPrefix());
				// add also the real IP address to eth0
				Ip4Address ext_addr=null;
				for (Enumeration<InetAddress> e=NetworkInterface.getByName(r0_ext_if).getInetAddresses(); ; e.hasMoreElements()) {
					InetAddress iaddr=e.nextElement();
					if (iaddr instanceof Inet4Address) {
						Ip4Address addr=new Ip4Address(iaddr);
						//System.out.println("DEBUG: ext address: "+addr);
						if (r0_ext_addr_prefix.getPrefix().contains(addr)) {
							ext_addr=addr;
							break;
						}
					}
				}
				if (ext_addr!=null) {
					Ip4AddressPrefix r0_ext_2=new Ip4AddressPrefix(ext_addr,r0_ext_addr_prefix.getPrefixLength());			
					System.out.println("R00 external interface real address: "+r0_ext_2.toStringWithPrefixLength());
					r0_eth0.addAddress(r0_ext_2);
				}
				routers[0]=new Ip4Router(new NetInterface[]{r0_eth0, r0_eth1});
				routers[0].setDynamicRouting(routing);
			}
			else {
				ext_link=new DataLink();
				NetInterface r0_eth0=new DataLinkInterface(ext_link,r0_ext_addr_prefix);
				NetInterface r0_eth1=new DataLinkInterface(links[0],links[0].nextAddressPrefix());
				routers[0]=new Ip4Router(new NetInterface[]{r0_eth0, r0_eth1});				
				routers[0].setDynamicRouting(routing);
			}
			
			// create all other routers Ri (i=1,2,..,n-1)
			for (int i=1; i<n; i++) {
				routers[i]=new Ip4Router(new IpLink[]{links[i-1],links[i]});
				routers[i].setDynamicRouting(routing);
			}
			//System.out.println("Network graph: "+spf.getNetworkGraph().toString());
			
			// update all routing tables
			System.out.println(algo.toString()+" algorithm is used");
			long start_time=System.currentTimeMillis();
			routing.updateAllNodes();
			System.out.println("Computation time: "+(System.currentTimeMillis()-start_time)+" ms\n");
			System.out.println("R0-RT:\n"+routers[0].getRoutingTable().toString());
			System.out.println("DataLink bit-rate: "+(LINK_BIT_RATE>=1000000? ""+(LINK_BIT_RATE/1000000D)+" Mb/s" : ""+(LINK_BIT_RATE/1000D)+" kb/s")+"\n");
			
			// tcpdump
			if (tcpdump) {
				NetInterface[] pints=new PromiscuousLinkInterface[n];
				for (int i=0; i<n; i++) pints[i]=new PromiscuousLinkInterface(links[i],new Ip4Address("10."+i+".0.254"));
				new Sniffer(pints,sniffer_listener);
			}
			
			// create host H2
			Ip4AddressPrefix h2=(Ip4AddressPrefix)links[n-1].nextAddressPrefix();
			NetInterface h2_eth0=new DataLinkInterface(links[n-1],h2);
			final Ip4Layer host2=new Ip4Layer(new NetInterface[]{h2_eth0});		
			host2.getRoutingTable().setDefaultRoute(new Route(null,new Ip4Address("10."+(n-1)+".0.1"),h2_eth0));
			System.out.println("H2 running at "+h2);

			if (udp_echo) {
				// H2 transport layer
				DatagramSocket udp_socket=new DatagramSocket(new UdpLayer(host2),5555);
				DatagramPacket datagram_packet=new DatagramPacket(new byte[1024],0);
				while (true) {
					udp_socket.receive(datagram_packet);
					System.out.println("UDP ECHO: received data: "+ByteUtils.asHex(datagram_packet.getData(),datagram_packet.getOffset(),datagram_packet.getLength()));
					datagram_packet.setPort(5555);
					System.out.println("UDP ECHO: reply to: "+datagram_packet.getAddress().getHostAddress().toString());			
					udp_socket.send(datagram_packet);
				}				
			}
			// ping H2
			if (r0_ext_if==null) {
				Ip4AddressPrefix local_addr_prefix=(Ip4AddressPrefix)IpAddressUtils.addressPrefix(r0_ext_addr_prefix.getPrefix(),new Ip4Address("0.0.0.99"));
				DataLinkInterface link_interface=new DataLinkInterface(ext_link,local_addr_prefix);
				//link_interface.send(new IcmpEchoRequestMessage(local_addr_prefix,h1,0,0,"0123456789".getBytes()).toIp4Packet(),r0_1_1);
				Ip4Layer ip_layer=new Ip4Layer(new DataLinkInterface[]{link_interface});
				ip_layer.getRoutingTable().setDefaultRoute(r0_ext_addr_prefix);
				new PingClient(ip_layer,0,"0123456789".getBytes(),h2,ping_count,ping_time,System.out);
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}*/

	
	/** IPv4 Manhattan topology with NxN routers, and one host.
	 * The router R00 may be a gateway connected to external network.
	 * @param n nxn is the size of the network
	 * @param ext_ni external interface of R00 (or null in case of virtual interface)
	 * @param ext_addr_prefix IPv4 address and prefix length on the external interface of R00
	 * @param k the index of the network where the host is attached
	 * @param algo shortest-path algorithm
	 * @param tcpdump whether running tcpdump
	 * @param ping_count number of ping requests
	 * @param ping_time time between ping requests */
	private static void testManhattan(int n, String ext_ni, Ip4AddressPrefix ext_addr_prefix, Ip4Address ext_gw, int k, ShortestPathAlgorithm algo, boolean tcpdump, int ping_count, long ping_time) {
		System.out.println("Network topology: "+n+"x"+n+" Manhattan");
		try {
			// create all links
			IpLink[] links=new IpLink[2*n*n];
			for (int i=0; i<n; i++) {
				for (int j=0; j<n; j++) {
					int index=i*n+j;
					links[2*index]=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10."+i+"."+j+".0/25"));
					links[2*index+1]=new IpLink(LINK_BIT_RATE,new Ip4Prefix("10."+i+"."+j+".128/25"));
				}
			}
			
			// array of routers
			Ip4Router[] routers=new Ip4Router[n*n];	
			
			// dynamic routing
			SdnRouting routing=new SdnRouting(algo);

			// create the first router (R0)
			System.out.println("R0 external interface address: "+ext_addr_prefix);
			NetInterface r0_eth1=new DataLinkInterface(links[0],links[0].nextAddressPrefix());
			NetInterface r0_eth2=new DataLinkInterface(links[1],links[1].nextAddressPrefix());
			DataLink ext_link=null;
			NetInterface r0_eth0=null;			
			if (ext_ni!=null) {
				// real interface
				boolean is_tuntap=ext_ni.startsWith("tun") || ext_ni.startsWith("tap") || ext_ni.startsWith("utun");
				if (is_tuntap) {
					r0_eth0=new Ip4TuntapInterface(ext_ni, ext_addr_prefix);
				}
				else {
					r0_eth0=new Ip4EthInterface(new RawEthInterface(ext_ni),ext_addr_prefix);
					// add the current address as second IP address
					Ip4Address ext_addr=null;
					for (Enumeration<InetAddress> e=NetworkInterface.getByName(ext_ni).getInetAddresses(); ; e.hasMoreElements()) {
						InetAddress iaddr=e.nextElement();
						if (iaddr instanceof Inet4Address) {
							Ip4Address addr=new Ip4Address(iaddr);
							//System.out.println("DEBUG: ext address: "+addr);
							if (ext_addr_prefix.getPrefix().contains(addr)) {
								ext_addr=addr;
								break;
							}
						}
					}
					if (ext_addr!=null) {
						Ip4AddressPrefix r0_ext_2=new Ip4AddressPrefix(ext_addr,ext_addr_prefix.getPrefixLength());			
						r0_eth0.addAddress(r0_ext_2);
						System.out.println("R0 external interface real address: "+r0_ext_2.toStringWithPrefixLength());
					}				
				}
			}
			else {
				// virtual interface
				ext_link=new DataLink();
				r0_eth0=new DataLinkInterface(ext_link,ext_addr_prefix);
			}
			routers[0]=new Ip4Router(new NetInterface[]{r0_eth0, r0_eth1, r0_eth2});				
			routers[0].setDynamicRouting(routing);
			
			// create all other routers R_i,j
			for (int i=0; i<n; i++) {
				for (int j=0; j<n; j++) {
					if (i!=0 || j!=0) {
						int index=i*n+j;
						ArrayList<IpLink> router_links=new ArrayList<IpLink>();
						router_links.add(links[2*index]);
						router_links.add(links[2*index+1]);
						if (i>0) router_links.add(links[2*(index-n)+1]);
						if (j>0) router_links.add(links[2*(index-1)]);
						routers[index]=new Ip4Router(router_links.toArray(new IpLink[]{}));
						routers[index].setDynamicRouting(routing);
					}
				}
			}
			Graph g=routing.getNetworkGraph();
			System.out.println("Routers: "+routers.length);
			System.out.println("Links: "+(links.length+1));
			System.out.println("Modified network graph: "+g.getNodes().size()+" nodes, "+g.getEdges().size()+" edges: "+g.toString());
			System.out.println("R0-RT:\n"+routers[0].getRoutingTable().toString());
			
			// update all routing tables
			System.out.println("Shortest-path algorithm: "+algo.toString());
			long start_time=System.currentTimeMillis();
			/*for (int i=0; i<n*n; i++) {
				RoutingTable rt=routers[i].getRoutingTable();
				for (int j=0; j<(i-1); j++) rt.add(links[j].getPrefix(),new Ip4Address("10."+(i-1)+".0.1"));
				for (int j=i+1; j<n; j++) rt.add(links[j].getPrefix(),new Ip4Address("10."+i+".0.2"));
				if (i>0) rt.add(r0_1_1.getPrefix(),new Ip4Address("10."+(i-1)+".0.1"));
			}
			*/
			routing.updateAllNodes();
			if (ext_gw!=null) routers[0].getRoutingTable().add(new Route(Ip4Prefix.ANY,ext_gw,r0_eth0));

			System.out.println("Computation time: "+(System.currentTimeMillis()-start_time)+" ms\n");
			System.out.println("R0-RT:\n"+routers[0].getRoutingTable().toString());
			System.out.println("DataLink bit-rate: "+(LINK_BIT_RATE>=1000000? ""+(LINK_BIT_RATE/1000000D)+" Mb/s" : ""+(LINK_BIT_RATE/1000D)+" kb/s")+"\n");
			
			// tcpdump
			if (tcpdump) {
				NetInterface[] pints=new PromiscuousLinkInterface[2*n*n];
				for (int i=0; i<n; i++) {
					for (int j=0; j<n; j++) {
						int index=i*n+j;
						pints[2*index]=new PromiscuousLinkInterface(links[2*index],new Ip4Address("10."+i+"."+j+".126"));
						pints[2*index+1]=new PromiscuousLinkInterface(links[2*index+1],new Ip4Address("10."+i+"."+j+".254"));
					}
				}
				new Sniffer(pints,sniffer_listener);
			}
			
			// create host H2
			/*final Ip4Layer host2=new Ip4Layer(new NetInterface[]{h2_eth0});
			host2.getRoutingTable().setDefaultRoute(new Route(null,new Ip4Address("10."+((k/2)/n)+"."+((k/2)%n)+"."+(1+(k%2)*128)),h2_eth0));
			System.out.println("H2 running at "+h2);
			if (udp_echo) {
				// H2 transport layer
				DatagramSocket udp_socket=new DatagramSocket(new UdpLayer(host2),5555);
				DatagramPacket datagram_packet=new DatagramPacket(new byte[1024],0);
				while (true) {
					udp_socket.receive(datagram_packet);
					System.out.println("UDP ECHO: received data: "+ByteUtils.asHex(datagram_packet.getData(),datagram_packet.getOffset(),datagram_packet.getLength()));
					datagram_packet.setPort(5555);
					System.out.println("UDP ECHO: reply to: "+datagram_packet.getAddress().getHostAddress().toString());			
					udp_socket.send(datagram_packet);
				}
			}*/
			Ip4AddressPrefix h2=(Ip4AddressPrefix)links[k].nextAddressPrefix();
			NetInterface h2_eth0=new DataLinkInterface(links[k],h2);
			Ip4Address gw=new Ip4Address("10."+((k/2)/n)+"."+((k/2)%n)+"."+(1+(k%2)*128));
			Ip4Host host2=new Ip4Host(h2_eth0,gw);
			System.out.println("H2 running at "+h2);
			if (ext_ni!=null) {
				// start also a UDP echo server and a HTTP server
				host2.startUdpEchoServer();
				host2.startHttpServer();				
			}
			else {
				// ping
				Ip4AddressPrefix local_addr_prefix=(Ip4AddressPrefix)IpAddressUtils.addressPrefix(ext_addr_prefix.getPrefix(),new Ip4Address("0.0.0.99"));
				DataLinkInterface link_interface=new DataLinkInterface(ext_link,local_addr_prefix);
				//link_interface.send(new IcmpEchoRequestMessage(local_addr_prefix,h1,0,0,"0123456789".getBytes()).toIp4Packet(),r0_1_1);
				Ip4Layer ip_layer=new Ip4Layer(new DataLinkInterface[]{link_interface});
				ip_layer.getRoutingTable().setDefaultRoute(ext_addr_prefix);
				System.out.println("H1 running at "+local_addr_prefix);
				new PingClient(ip_layer,0,"0123456789".getBytes(),h2,ping_count,ping_time,System.out);
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	
	/** Main method. */
	public static void main(String[] args) {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		boolean verbose=flags.getBoolean("-v","verbode mode");
		//boolean linear=flags.getBoolean("-linear","whether using a linear topology in place of Manhattan");
		int n=flags.getInteger("-n","<num>",4,"number of nodes in a row; in case of Manhattan topology the number of node is nxn");
		int k=flags.getInteger("-k","<num>",2*n*n-1,"index of the network where the host is attached");
		LINK_BIT_RATE=flags.getLong("-b","<bit-rate>",LINK_BIT_RATE,"link bit rate [b/s]");
		boolean tcpdump=flags.getBoolean("-tcpdump","dump of packets");
		//boolean hybrid=flags.getBoolean("-hybrid","whether using external interface");
		//String ext_if=flags.getString("-i","<interface>",null,"external interface attachet to router R00");
		//Ip4AddressPrefix ext_addr_prefix=new Ip4AddressPrefix(flags.getString("-a","<address-prefix>","192.168.100.51/24","address and prefix length on the external interface of router R00"));
		String ext_ni=null;
		Ip4AddressPrefix ext_addr_prefix=new Ip4AddressPrefix("172.30.0.1/24");
		Ip4Address ext_gw=null;
		String ext=flags.getString("-i","<if/addr/len/gw>",null,"name, IPv4 address, prefix length, gateway for the external interface of router R00 (e.g. tun0/172.16.0.2/24/172.16.0.1)");
		if (ext!=null) {
			String[] tokens=ext.split("/");
			ext_ni=tokens[0];
			ext_addr_prefix=new Ip4AddressPrefix(tokens[1],Integer.valueOf(tokens[2]));
			ext_gw=new Ip4Address(tokens[3]);
		}
		int ping_count=flags.getInteger("-c","<num>",3,"number of ping requests");
		long ping_time=flags.getLong("-t","<time>",1000,"ping inter-time [millisec]");
		String algo_name=flags.getString("-algo","<algo>","sim","shortest-path alorithm");
		
		if (help) {
			System.out.println(flags.toUsageString(IPv4HybridRoutingTest.class.getName()));
			System.out.println("\nShortest-path algorithm:");
			System.out.println("    dijkstra  Dijkstra");
			System.out.println("    floyd     Floyd-Warshall");
			System.out.println("    bellman   Bellman-Ford");
			System.out.println("    simple    Dijkstra simplified");
			return;
		}

		if (verbose) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			//DataLink.DEBUG=true;
			//DataLinkInterface.DEBUG=true;
			//Ip4Link.DEBUG=true;
			Ip4EthInterface.DEBUG=true;
			Ip4TunInterface.DEBUG=true;
			TapInterface.DEBUG=true;
			Node.DEBUG=true;
			Ip4Node.DEBUG=true;
			Ip4Layer.DEBUG=true;
			UdpLayer.DEBUG=true;
		}

		ShortestPathAlgorithm algo;
		if (algo_name.toLowerCase().startsWith("dij")) algo=ShortestPathAlgorithm.DIJKSTRA;
		else
		if (algo_name.toLowerCase().startsWith("flo")) algo=ShortestPathAlgorithm.FLOYD_WARSHALL;
		else
		if (algo_name.toLowerCase().startsWith("bel")) algo=ShortestPathAlgorithm.BELLMAN_FORD;
		else
		if (algo_name.toLowerCase().startsWith("sim")) algo=ShortestPathAlgorithm.DIJKSTRA_SIMPLE;
		else throw new RuntimeException("Unsupported shortest-path algorithm: "+algo_name);

		//Clock.setDefaultClock(new VirtualClock());
		//testHybridRoute(tcpdump);
		
		//if (linear) testLinearNetwork(n,ext_if,ext_addr_prefix,algo,udp_echo,tcpdump,ping_count,ping_time);
		//else
		testManhattan(n,ext_ni,ext_addr_prefix,ext_gw,k,algo,tcpdump,ping_count,ping_time);
	}

}
