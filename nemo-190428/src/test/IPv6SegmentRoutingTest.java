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


import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Node;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.ipstack.ip6.exthdr.SegmentRoutingHeader;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;
import it.unipr.netsec.ipstack.udp.UdpPacket;
import it.unipr.netsec.ipstack.util.IpAddressUtils;
import it.unipr.netsec.nemo.ip.Ip6Host;
import it.unipr.netsec.nemo.ip.Ip6Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.DataLink;
import it.unipr.netsec.nemo.link.DataLinkInterface;
import it.unipr.netsec.nemo.link.Network;
import it.unipr.netsec.nemo.link.NetworkBuilder;
import it.unipr.netsec.simulator.scheduler.VirtualClock;

import org.zoolu.util.Clock;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import java.util.Arrays;


/** Test routing.
 */
public class IPv6SegmentRoutingTest {

	/** DataLink bit rate */
	private static long LINK_BIT_RATE=1000L;

	/** Network prefix */
	private static IpPrefix NET_PREFIX=new Ip6Prefix("fc00::/16");
	
	/** Network prefix used for configuring router loopback addresses */
	//private static IpPrefix LOOPBACK_PREFIX=new Ip6Prefix("fd00::/16");

	
	/** IPv6 network formed by two routers and three links.
	 * <p>
	 * In this test, a single network (link) is created with 2 hosts (H1 and H2)
	 * and 4 routers (R1, R2, R3, R4).
	 * <p>
	 * H1 sends packets to H2 with segment list = { R1, R2, R3, H2 }. */
	public static void testSegmentRouting() {
		Ip6AddressPrefix h1=new Ip6AddressPrefix("fc00:1::1001/64");
		Ip6AddressPrefix h2=new Ip6AddressPrefix("fc00:1::1002/64");
		Ip6AddressPrefix r1=new Ip6AddressPrefix("fc00:1::1/64");
		Ip6AddressPrefix r2=new Ip6AddressPrefix("fc00:1::2/64");
		Ip6AddressPrefix r3=new Ip6AddressPrefix("fc00:1::3/64");
		Ip6AddressPrefix r4=new Ip6AddressPrefix("fc00:1::4/64");
		
		DataLink link1=new DataLink(LINK_BIT_RATE);

		DataLinkInterface h1_eth0=new DataLinkInterface(link1,h1);
		Ip6Host host1=new Ip6Host(h1_eth0,r1);	

		DataLinkInterface h2_eth0=new DataLinkInterface(link1,h2);
		final long start_time=Clock.getDefaultClock().currentTimeMillis();
		Ip6Host host2=new Ip6Host(h2_eth0,r1) {
			@Override
			protected void processReceivedPacket(NetInterface ni, Packet pkt) {
				super.processReceivedPacket(ni,pkt);
				System.out.println("H2 received packet: "+pkt);
				System.out.println("total time: "+(Clock.getDefaultClock().currentTimeMillis()-start_time)+" ms");
			}
		};
		
		DataLinkInterface r1_eth0=new DataLinkInterface(link1,r1);
		Ip6Router router1=new Ip6Router(r1,new DataLinkInterface[]{r1_eth0});
		
		DataLinkInterface r2_eth0=new DataLinkInterface(link1,r2);
		Ip6Router router2=new Ip6Router(r2,new DataLinkInterface[]{r2_eth0});

		DataLinkInterface r3_eth0=new DataLinkInterface(link1,r3);
		Ip6Router router3=new Ip6Router(r3,new DataLinkInterface[]{r3_eth0});

		DataLinkInterface r4_eth0=new DataLinkInterface(link1,r4);
		Ip6Router router4=new Ip6Router(r4,new DataLinkInterface[]{r4_eth0});
		
		//System.out.println("R1-RT:\n"+router1.getRoutes());
				
		int proto=66; // just for testing
		Ip6Packet ip6_pkt=new Ip6Packet(h1,r1,proto,"test".getBytes());
		Ip6Address[] reverse_segment_list=new Ip6Address[]{ h2, r3, r2, r1 };
		System.out.println("Reverse segment list: "+Arrays.toString(reverse_segment_list));

		SegmentRoutingHeader srh=new SegmentRoutingHeader(reverse_segment_list);
		srh.setCleanupFlag(true);
		ip6_pkt.addExtHdr(srh);
		host1.sendPacket(ip6_pkt);
	}

	
	/** Linear network with <i>n</i> routers and <i>n+1</i>links, or Manhattan network with n*n routers and 2(n^2)+2n links.
	 * <p>
	 * H1 sends packets to H2 with <i>k+1</i> segments, where the first segment is the first router,
	 * the second segment is the last router, the third segment is the first router and so on.
	 * The last segment is the destination host H2.
	 * <p>
	 * If <i>k</i> is even, the <i>k-th</i>segment is the last router and 
	 * there are <i>(k-1)*n</i> hops.
	 * If <i>k</i> is odd, the <i>k-th</i> segment is the first router and 
	 * there are <i>k*n</i> hops. */
	public static void testSegmentRouting(boolean manhattan, int n, int k) {
		
		//int prefix_len=NET_PREFIX.prefixLength()+16-IpAddressUtils.ceilLog2(n+2);
		int prefix_len=manhattan? NET_PREFIX.prefixLength()+16-IpAddressUtils.ceilLog2(2*n*(n+1)) : NET_PREFIX.prefixLength()+16-IpAddressUtils.ceilLog2(n+1);
		NET_PREFIX=IpAddressUtils.subnet(NET_PREFIX,prefix_len,0);

		Network network=manhattan? NetworkBuilder.manhattanIpNetwork(n,n,LINK_BIT_RATE,NET_PREFIX) : NetworkBuilder.linearIpNetwork(n,LINK_BIT_RATE,NET_PREFIX);
		System.out.println("Network: "+network);		
		
		IpLink[] links=(IpLink[])network.getAccessLinks();
		IpLink link1=links[0];
		IpLink link2=links[links.length-1];
		
		Node[] routers=network.getNodes();
		IpPrefix prefix1=link1.getPrefix();
		IpPrefix prefix2=link2.getPrefix();
		IpAddress h1_addr=IpAddressUtils.addressPrefix(prefix1,"::1001");	
		IpAddress h2_addr=IpAddressUtils.addressPrefix(prefix2,"::1001");
		Node router1=routers[0];
		Node router2=routers[routers.length-1];
		/*System.out.println("DEBUG: R1: "+router1);
		System.out.println("DEBUG: R2: "+router2);
		System.out.println("DEBUG: link1: "+link1.getPrefix());
		System.out.println("DEBUG: link2: "+link2.getPrefix());*/
		
		final long start_time=Clock.getDefaultClock().currentTimeMillis();

		Ip6Host host1=new Ip6Host(new DataLinkInterface(link1,h1_addr),(IpAddress)router1.getNetInterfaces()[0].getAddresses()[0]);	
		Ip6Host host2=new Ip6Host(new DataLinkInterface(link2,h2_addr),(IpAddress)router2.getNetInterfaces()[manhattan?3:1].getAddresses()[0]){
			@Override
			protected void processReceivedPacket(NetInterface ni, Packet pkt) {
				super.processReceivedPacket(ni,pkt);
				System.out.println("H2 received packet: "+pkt);
				System.out.println("total time: "+(Clock.getDefaultClock().currentTimeMillis()-start_time)+" ms");
			}
		};
						
		UdpPacket udp_pkt=new UdpPacket(h1_addr,4000,h2_addr,4000,"test".getBytes());
		
		Ip6Address[] reverse_segment_list=new Ip6Address[k+1];
		reverse_segment_list[0]=(Ip6Address)udp_pkt.getDestAddress();
		//for (int i=0; i<k; i++) reverse_segment_list[k-i]=new Ip6Address(NET_PREFIX+(i*n/k)+"::1");
		for (int i=0; i<k; i++) reverse_segment_list[k-i]=(i%2==0)? (Ip6Address)router1.getNetInterfaces()[0].getAddresses()[0] : (Ip6Address)router2.getNetInterfaces()[0].getAddresses()[0];
		System.out.println("Reverse segment list: "+Arrays.toString(reverse_segment_list));
				
		SegmentRoutingHeader srh=new SegmentRoutingHeader(reverse_segment_list);
		srh.setCleanupFlag(true);

		Ip6Address src_ipaddr=(Ip6Address)udp_pkt.getSourceAddress();
		Ip6Address dst_ipaddr=(Ip6Address)udp_pkt.getDestAddress();
		Ip6Packet ip6_pkt=new Ip6Packet(src_ipaddr,dst_ipaddr,Ip6Packet.IPPROTO_UDP,udp_pkt.getBytes());
		ip6_pkt.addExtHdr(srh);
		ip6_pkt.setDestAddress(srh.getSegmentAt(srh.getSegmentLeft()));
		//System.out.println("IPv6 pkt: "+ByteUtils.asHex(ip6_pkt.getBytes()));
		host1.sendPacket(ip6_pkt);
	}
	
	
	/** Main method. 
	 * @throws InterruptedException */
	public static void main(String[] args) throws InterruptedException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		boolean verbose=flags.getBoolean("-v","verbose mode");
		int n=flags.getInteger("-n","<routers>",-1,"number of routers with linear topology");
		int segments=flags.getInteger("-k","<segments>",0,"number of intermediate segments");
		boolean manhattan=flags.getBoolean("-q","Manhattan topology with nxn routers");
		
		if (help) {
			System.out.println(flags.toUsageString(IPv6SegmentRoutingTest.class.getName()));
			return;
		}
		// else
		if (verbose) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			Node.DEBUG=true;
			Ip6Node.DEBUG=true;			
			Ip6Router.DEBUG=true;			
		}
		Ip4Packet.DEFAULT_TTL=255;
		Clock.setDefaultClock(new VirtualClock());
		
		if (n<=0) testSegmentRouting();
		else testSegmentRouting(manhattan,n,segments);
	}

}
