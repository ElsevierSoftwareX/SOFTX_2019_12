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

package it.unipr.netsec.ipstack.nat;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.tcp.TcpPacket;
import it.unipr.netsec.ipstack.udp.UdpPacket;

import java.util.HashMap;
import java.util.Random;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** S-D-NAT node.
 * It is a special D-NAT (destination NAT) that modifies also the source address of incoming packets
 * that are targeted to known destination addresses.
 * <p>
 * Like a standard D-NAT, the destination address of an incoming packet is uses as key
 * of a static lookup table (NAT table) that specifies address mappings.
 * If an table entry matches that destination address, the destination address is changed accordingly
 * with that entry. <br>
 * In addition, the S-D-NAT changes also the source address of the packet based on the matching table entry.
 * The original source address is dynamically stored in the NAT table in such a way that, if the target node
 * replies back to this packet, the destination address is replaced with stored address of the originating node.
 * <p>
 * Each entry of the static NAT table contains: the target destination address of the incoming packet,
 * the new destination address, and the new source address. <br>
 * These table entries must be explicitly set through the {@link #add(Address, Address, Address)} method.
 * <p>
 * Note: This S-D-NAT acts as simple NAT, modifying only the addresses within the IP header. Port numbers of the transport headers remain unchanged.
 */
public class SDestNAT extends Ip4Node {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.INFO,"D-NAT: "+str);
	}
	
	
	/** D-NAT table */
	HashMap<Address,AddressPair> dnat_table=new HashMap<Address,AddressPair>();
	
	/** Error rate */
	double err=0;

	/** Random number generator */
	Random rand=new Random();

	
	/** Creates a new NAT.
	 * @param net_interfaces the network interfaces */
	public SDestNAT(NetInterface[] net_interfaces) {
		super(net_interfaces);
		setForwarding(true);
	}

	@Override
	protected void processForwardingPacket(Packet pkt) {
		if (err>0 && rand.nextDouble()<err) return;
		Ip4Packet ip_pkt=(Ip4Packet)pkt;
		ip_pkt=mangle(ip_pkt);
		if (ip_pkt!=null) super.processForwardingPacket(ip_pkt);
	}	
	
	/** Function that mangles incoming packets before forwarding. */
	private Ip4Packet mangle(Ip4Packet ip_pkt) {
		Ip4Address in_src_addr=(Ip4Address)ip_pkt.getSourceAddress();
		Ip4Address in_dst_addr=(Ip4Address)ip_pkt.getDestAddress();
		
		if (dnat_table.containsKey(in_dst_addr)) {
			AddressPair mapping=dnat_table.get(in_dst_addr);
			Ip4Address out_src_addr=(Ip4Address)mapping.getSourceAddress();
			Ip4Address out_dst_addr=(Ip4Address)mapping.getDestAddress();
			if (out_src_addr==null) out_src_addr=in_src_addr;
			
			if (!dnat_table.containsKey(out_src_addr)) {
				dnat_table.put(out_src_addr,new AddressPair(in_dst_addr,in_src_addr));
			}
			
			int proto=ip_pkt.getProto();
			if (proto==Ip4Packet.IPPROTO_UDP) {
				UdpPacket udp_pkt=UdpPacket.parseUdpPacket(ip_pkt);
				if (DEBUG) debug("Recv: "+udp_pkt);
				udp_pkt.setSourceAddress(out_src_addr);
				udp_pkt.setDestAddress(out_dst_addr);
				if (DEBUG) debug("Send: "+udp_pkt);
				return udp_pkt.toIp4Packet();
			}
			else
			if (proto==Ip4Packet.IPPROTO_TCP) {
				TcpPacket tcp_pkt=TcpPacket.parseTcpPacket(ip_pkt);
				if (DEBUG) debug("Recv: "+tcp_pkt);
				tcp_pkt.setSourceAddress(out_src_addr);
				tcp_pkt.setDestAddress(out_dst_addr);
				if (DEBUG) debug("Send: "+tcp_pkt);
				return tcp_pkt.toIp4Packet();
			}
			else {
				if (DEBUG) debug("Recv: "+ip_pkt);
				ip_pkt=new Ip4Packet(out_src_addr,out_dst_addr,ip_pkt.getProto(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
				if (DEBUG) debug("Send: "+ip_pkt);
				return ip_pkt;
			}
		}
		// else
		if (DEBUG) debug("Recv: "+ip_pkt);
		if (DEBUG) debug("No D-NAT mapping found: packet discarded");
		return null;
	}
	
	/** Adds a D-NAT mapping.
	 * @param in_dst_addr destination address of incoming packet
	 * @param out_src_addr source address of the modified outgoing packet
	 * @param out_dst_addr destination address of the modified outgoing packet */
	public void add(Address in_dst_addr, Address out_src_addr, Address out_dst_addr) {
		if (DEBUG) debug("add(): "+in_dst_addr+" -> "+out_src_addr+","+out_dst_addr);
		dnat_table.put(in_dst_addr,new AddressPair(out_src_addr,out_dst_addr));
	}

	/** Removes a D-NAT mapping.
	 * @param in_dst_addr input destination address of the entry to be deleted */
	public void remove(Address in_dst_addr) {
		if (DEBUG) debug("remove: "+in_dst_addr);
		dnat_table.remove(in_dst_addr);
	}

	
	/** Address pair formed by a source and a destination address.
	 */
	private static class AddressPair {

		/** New source address */
		public Address src_addr;

		/** New destination address */
		public Address dst_addr;

		
		/** Creates a new pair.
		 * @param src_addr source address
		 * @param dst_addr destination address */
		public AddressPair(Address src_addr, Address dst_addr) {
			this.src_addr=src_addr;
			this.dst_addr=dst_addr;
		}
		
		/** Gets the source address. */
		public Address getSourceAddress() {
			return src_addr;
		}	
		
		/** Gets the dest address. */
		public Address getDestAddress() {
			return dst_addr;
		}
	}
	
}
