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
import it.unipr.netsec.nemo.ip.Ip6Host;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.DataLink;
import it.unipr.netsec.nemo.link.Network;
import it.unipr.netsec.nemo.link.NetworkBuilder;
import it.unipr.netsec.nemo.link.PacketGenerator;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.routing.RoutingTable;
import it.unipr.netsec.ipstack.udp.UdpPacket;
import it.unipr.netsec.ipstack.util.IpAddressUtils;
import it.unipr.netsec.simulator.scheduler.VirtualClock;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** Routing in IPv4 or IPv6 network with different topologies (Manhattan, tree, etc.).
 */
public class RoutingTest {

	/** Default bit rate [b/s] */
	static long DEFAULT_BIT_RATE=100000000L; // 100Mb/s
	//static long DEFAULT_BIT_RATE=0;

	/** Network prefix */
	//static IpPrefix NET_PREFIX4=new Ip4Prefix("172.16.0.0/12");
	static IpPrefix NET_PREFIX4=new Ip4Prefix("10.0.0.0/9");
	static IpPrefix NET_PREFIX6=new Ip6Prefix("fc00::/16");
	
	/** Default UDP payload length */
	//static int DEFAULT_PAYLOAD_LEN=512;
	static int DEFAULT_IP_PAYLOAD_LEN=1000;// -8-(NET_PREFIX instanceof Ip6Prefix? 40 : 20);

	/** Default network type */
	//static String DEFAULT_NETWORK_TYPE="manhattan 4 4";

	/** Default network size */
	//static int DEFAULT_NETWORK_SIZE=16;

	/** Verbose mode */
	static boolean VERBOSE=false;

	/** Whether pausing after each run */
	static boolean PAUSE=false;

	
	/** Test with a given network.
	 * @param type network type (e.g. "linerar", "manhattan", "tree", "tree3", "tree4", etc.)
	 * @param n network size parameter (depends on the type of network)
	 * @param bit_rate link bit-rate
	 * @param net_prefix IP super-network prefix
	 * @param payload_len UDP payload size
	 * @param count number of ping requests
	 * @param pg_size if &gt;0, a packet generator is used in place of PING, with the given packet size
	 * @param print_routing_tables prints routing table of the first router */
	private static void testNetwork(String type, int n, long bit_rate, IpPrefix net_prefix, long count, int pg_size, boolean print_routing_table) {
		Network network;
		if (type.toLowerCase().startsWith("alt")) {
			network=NetworkBuilder.linearIpNetworkAlt(n,bit_rate,net_prefix);
		}
		else
		if (type.toLowerCase().startsWith("lin")) {
			network=NetworkBuilder.linearIpNetwork(n,bit_rate,net_prefix);
		}
		else
		if (type.toLowerCase().startsWith("man")) {
			network=NetworkBuilder.manhattanIpNetwork(n,n,bit_rate,net_prefix);
		}
		else
		if (type.toLowerCase().startsWith("tree")) {
			int degree=type.length()>4? Integer.parseInt(type.substring(4)) : 2;
			network=NetworkBuilder.treeIpCoreNetwork(degree,n,bit_rate,net_prefix);
		}
		else throw new RuntimeException("Unknown network type: "+type);
		
		if (VERBOSE) System.out.println("Network: "+network);
		IpLink[] links=(IpLink[])network.getAccessLinks();
		// SRC point
		IpLink link1=links[0];
		IpAddress r1_addr=link1.getRouters()[0];
		IpPrefix prefix1=link1.getPrefix();
		IpAddress h1_addr=IpAddressUtils.addressPrefix(prefix1,2);
		if (VERBOSE) System.out.println("Source: h1="+h1_addr+"/"+prefix1.prefixLength()+", gw="+r1_addr);
		
		// DST point
		IpLink link2=links[links.length-1];
		IpAddress r2_addr=link2.getRouters()[0];
		IpPrefix prefix2=link2.getPrefix();
		IpAddress h2_addr=IpAddressUtils.addressPrefix(prefix2,2);
		if (VERBOSE) System.out.println("Target: h2="+h2_addr+"/"+prefix2.prefixLength()+", gw="+r2_addr);
		
		if (print_routing_table) {
			System.out.println("R0-RT:\n"+((RoutingTable)network.getNodes()[0].getRoutingFunction()).toStringWithSpaces()+"\n");
		}
		
		if (pg_size<=0) {
			// PING test
			if (h1_addr instanceof Ip4Address) {
				Ip4Host host1=new Ip4Host(link1,(Ip4Address)h1_addr,(Ip4Address)r1_addr);
				Ip4Host host2=new Ip4Host(link2,(Ip4Address)h2_addr,(Ip4Address)r2_addr);
				System.out.println("From "+host1.getAddress()+":");
				host1.ping(host2.getAddress(),(int)count,System.out);				
			} else {
				Ip6Host host1=new Ip6Host(link1,(Ip6Address)h1_addr,(Ip6Address)r1_addr);
				Ip6Host host2=new Ip6Host(link2,(Ip6Address)h2_addr,(Ip6Address)r2_addr);
				System.out.println("From "+host1.getAddress()+":");
				host1.ping(host2.getAddress(),(int)count,System.out);								
			}
		}
		else {
			// PACKET GENERATOR TEST
			PacketGenerator pg=new PacketGenerator(link1,h1_addr,link2,h2_addr);
			UdpPacket udp_pkt=new UdpPacket(h1_addr,4000,h2_addr,4000,new byte[pg_size-8-(h1_addr instanceof Ip4Address?20:40)]);
			Packet ip_pkt=h1_addr instanceof Ip4Address? udp_pkt.toIp4Packet() : udp_pkt.toIp6Packet();
			pg.send(ip_pkt,r1_addr,count,0,null);
			System.out.print(""+n
					+'\t'+network.getNodes().length
					+'\t'+((network.getCoreLinks()!=null?network.getCoreLinks().length:0)+(network.getAccessLinks()!=null?network.getAccessLinks().length:0))
					+'\t'+pg.getHopNumber()
					+'\t'+pg.getRxCount()
					+'\t'+ip_pkt.getPacketLength()
					+'\t'+pg.getVirtualTime()
					+'\t'+pg.getRealTime()/1000
					+'\n');
			// wait
			if (PAUSE) SystemUtils.readLine();			
		}
	}
		

	/** Main method. 
	 * @throws InterruptedException */
	public static void main(String[] args) throws InterruptedException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		VERBOSE=flags.getBoolean("-v","verbose mode");
		long bit_rate=DateFormat.parseLongKMG(flags.getString("-b","<bit-rate>",String.valueOf(DEFAULT_BIT_RATE),"link capacity [b/s] (default is "+DateFormat.formatBitRate(DEFAULT_BIT_RATE)+")"));
		int count=flags.getInteger("-c","<count>",3,"number of ping messages");
		int n=flags.getInteger("-n","<size>",1,"network size n (e.g. manhattan nxn or tree height n)");
		int N=flags.getInteger("-N","<size>",n,"maximum network size n");
		String type=flags.getString("-t","<type>","alt","network type (manhattan, linear, tree, tree3, tree4, etc)");
		boolean ipv6=flags.getBoolean("-6","uses an IPv6 network");
		boolean print_routing_table=flags.getBoolean("-r","prints the routing table of the first router");
		int packet_generator=flags.getInteger("-g","<size>",-1,"uses a packet generator in place of ping, with the given packet size");
		boolean virtual_time=flags.getBoolean("-z","uses virtual time");
		PAUSE=flags.getBoolean("-pause","pauses after each run");
		
		if (VERBOSE) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			DataLink.DEBUG=true;
			Node.DEBUG=true;
		}
		
		if (help) {
			System.out.println(flags.toUsageString(RoutingTest.class.getSimpleName()));
			System.out.println();
			System.out.println("By default, it is used an IPv4 linear network with 1 router, two links, and link capacity="+DateFormat.formatBitRate(DEFAULT_BIT_RATE)+".");
			return;
		}

		if (virtual_time) Clock.setDefaultClock(new VirtualClock());
		Ip4Packet.DEFAULT_TTL=255;
		IpPrefix net_prefix=ipv6? NET_PREFIX6 : NET_PREFIX4;

		// print recap info
		if (type.toLowerCase().startsWith("lin") || type.toLowerCase().startsWith("alt")) {
			if (N==n) System.out.println("Linear network, routers="+n+", links="+(n+1)+", bit-rate="+DateFormat.formatBitRate(bit_rate));
			else System.out.println("Linear network, routers=n, links=n+1, bit-rate="+DateFormat.formatBitRate(bit_rate));
		}
		else
		if (type.toLowerCase().startsWith("man")) {
			if (N==n) System.out.println("Manhattan network, routers="+(n*n)+", links="+(2*(n*n+n))+", bit-rate="+DateFormat.formatBitRate(bit_rate));
			else System.out.println("Manhattan network, routers=n^2, links=2(n^2+n), bit-rate="+DateFormat.formatBitRate(bit_rate));
		}
		else
		if (type.toLowerCase().startsWith("tree")) {
			int degree=type.length()>4? Integer.parseInt(type.substring(4)) : 2;
			if (N==n) System.out.println("Tree network, degree="+degree+", depth="+n+", routers="+(int)(Math.pow(degree,n+1)-1)/(degree-1)+", links="+(int)(Math.pow(degree,n+1)-2+Math.pow(degree,n))+", bit-rate="+DateFormat.formatBitRate(bit_rate));
			else System.out.println("Tree network, degree="+degree+", depth=n, routers="+(degree==2? "2^(n+1)-1" : "("+degree+"^(n+1)-1)/"+(degree-1))+",  links="+degree+"^(n+1)-2+"+degree+"^n, bit-rate="+DateFormat.formatBitRate(bit_rate));
		}
				
		if (PAUSE) System.out.println("After each run press 'ENTER' to go on.\n");
		if (packet_generator>0) {
			System.out.println("n\trouters\tlinks\thops\tpkts\tplen[B]\tt[us]\trt[ms]");
		}

		// run
		for (; n<=N; n++) {
			testNetwork(type,n,bit_rate,net_prefix,count,packet_generator,print_routing_table);
		}
		// sleep until the JVM is killed
		//Thread.currentThread().join();
	}

}
