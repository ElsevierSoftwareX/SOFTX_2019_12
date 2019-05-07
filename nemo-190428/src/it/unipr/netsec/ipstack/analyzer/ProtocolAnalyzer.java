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

package it.unipr.netsec.ipstack.analyzer;


import it.unipr.netsec.ipstack.arp.ArpPacket;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.ppp.PppEncapsulation;
import it.unipr.netsec.ipstack.slip.SlipPacket;
import it.unipr.netsec.ipstack.tcp.TcpPacket;
import it.unipr.netsec.ipstack.udp.UdpPacket;

import java.util.ArrayList;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;


/** Protocol analyzer.
 * It provides static methods for inspecting packets. It recursively analyzes packet header and payload of all inner packets.
 */
public class ProtocolAnalyzer {
	
	// No constructors are available.
	private ProtocolAnalyzer() {}


	/** Gets a packet dump.
	  * @param pkt the packet
	  * @return the dump formed by a timestamp and packet description */
	public static String packetDump(Packet pkt) {
		return packetDump(pkt,null);
	}

	
	/** Gets a packet dump. 
	  * @param pkt the packet
	  * @param ni the network interface (optional), or null
	  * @return the dump formed by: a timestamp, the name of the interface (optional), and packet description */
	public static String packetDump(Packet pkt, String ni) {
		StringBuffer sb=new StringBuffer();
		sb.append(DateFormat.formatHHmmssSSS(Clock.getDefaultClock().currentTimeMillis())).append(" ");
		if (ni!=null) sb.append("[").append(ni).append("] ");
		sb.append(ProtocolAnalyzer.exploreInner(pkt).toString());
		return sb.toString();
	}

	
	/** Gets the inner packets encapsulated within a given packet.
	  * @param pkt the external packet
	  * @return the inner packet */
	public static Packet exploreInner(Packet pkt) {
		ArrayList<Packet> list=explore(pkt);
		return list.get(list.size()-1);
	}

	
	/** Gets the list of all packets iteratively encapsulated within a given packet.
	  * @param pkt the packet
	  * @return the sequence of encapsulated packets, including the external packet */
	public static ArrayList<Packet> explore(Packet pkt) {
		if (pkt instanceof EthPacket) return explore((EthPacket)pkt);
		if (pkt instanceof SlipPacket) return explore((SlipPacket)pkt);
		if (pkt instanceof PppEncapsulation) return explore((PppEncapsulation)pkt);
		if (pkt instanceof Ip4Packet) return explore((Ip4Packet)pkt);
		if (pkt instanceof Ip6Packet) return explore((Ip6Packet)pkt);
		// else
		ArrayList<Packet> list=new ArrayList<Packet>();
		list.add(pkt);
		return list;
	}

	
	/** Gets the list of all packets iteratively encapsulated within a given Ethernet packet.
	  * @param eth_pkt the Ethernet packet
	  * @return the sequence of encapsulated packets, including the external Ethernet packet */
	protected static ArrayList<Packet> explore(EthPacket eth_pkt) {
		int type=eth_pkt.getType();
		ArrayList<Packet> list=null;
		switch (type) {
			case EthPacket.ETH_ARP : list=new ArrayList<Packet>(); list.add(ArpPacket.parseArpPacket(eth_pkt)); break;
			case EthPacket.ETH_IP4 : list=explore(Ip4Packet.parseIp4Packet(eth_pkt)); break;
			case EthPacket.ETH_IP6 : list=explore(Ip6Packet.parseIp6Packet(eth_pkt)); break;
		}
		if (list==null) list=new ArrayList<Packet>();
		list.add(0,eth_pkt);
		return list;
	}

	
	/** Gets the list of all packets iteratively encapsulated within a given SLIP packet.
	  * @param slip_pkt the SLIP packet
	  * @return the sequence of encapsulated packets, including the external SLIP packet */
	protected static ArrayList<Packet> explore(SlipPacket slip_pkt) {
		ArrayList<Packet> list=explore(Ip4Packet.parseIp4Packet(slip_pkt.getPayloadBuffer(),slip_pkt.getPayloadOffset(),slip_pkt.getPayloadLength()));
		list.add(0,slip_pkt);
		return list;
	}

	
	/** Gets the list of all packets iteratively encapsulated within a given PPP packet.
	  * @param ppp_pkt the Ethernet packet
	  * @return the sequence of encapsulated packets, including the external PPP packet */
	protected static ArrayList<Packet> explore(PppEncapsulation ppp_pkt) {
		int type=ppp_pkt.getProtocol();
		ArrayList<Packet> list=null;
		switch (type) {
			case EthPacket.ETH_IP4 : list=explore(Ip4Packet.parseIp4Packet(ppp_pkt.getPayloadBuffer(),ppp_pkt.getPayloadOffset(),ppp_pkt.getPayloadLength())); break;
			case EthPacket.ETH_IP6 : list=explore(Ip6Packet.parseIp6Packet(ppp_pkt.getPayloadBuffer(),ppp_pkt.getPayloadOffset(),ppp_pkt.getPayloadLength())); break;
		}
		if (list==null) list=new ArrayList<Packet>();
		list.add(0,ppp_pkt);
		return list;
	}

	
	/** Gets the list of all protocols encapsulated within a given IPv4 packet.
	  * @param ip_pkt the IPv4 packet
	  * @return the sequence of encapsulated packets, including the external IPv4 packet */
	protected static ArrayList<Packet> explore(Ip4Packet ip_pkt) {
		int type=ip_pkt.getProto();
		ArrayList<Packet> list=null;
		switch (type) {
			case Ip4Packet.IPPROTO_ICMP : list=new ArrayList<Packet>(); list.add(new IcmpMessage(ip_pkt)); break;
			case Ip4Packet.IPPROTO_IP : list=explore(Ip4Packet.parseIp4Packet(ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength())); break;
			case Ip4Packet.IPPROTO_IPV6 : list=explore(Ip6Packet.parseIp6Packet(ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength())); break;
			case Ip6Packet.IPPROTO_UDP : list=new ArrayList<Packet>(); list.add(UdpPacket.parseUdpPacket(ip_pkt)); break;
			case Ip6Packet.IPPROTO_TCP : list=new ArrayList<Packet>(); list.add(TcpPacket.parseTcpPacket(ip_pkt)); break;
		}
		if (list==null) list=new ArrayList<Packet>();
		list.add(0,ip_pkt);
		return list;
	}

	
	/** Gets the list of all protocols encapsulated within a given IPv6 packet.
	  * @param ip_pkt the IPv6 packet
	  * @return the sequence of encapsulated packets, including the external IPv6 packet */
	protected static ArrayList<Packet> explore(Ip6Packet ip_pkt) {
		int type=ip_pkt.getPayloadType();
		ArrayList<Packet> list=null;
		switch (type) {
			case Ip6Packet.IPPROTO_ICMP6 : list=new ArrayList<Packet>(); list.add(new Icmp6Message(ip_pkt)); break;
			case Ip6Packet.IPPROTO_IP : list=explore(Ip4Packet.parseIp4Packet(ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength())); break;
			case Ip6Packet.IPPROTO_IPV6 : list=explore(Ip6Packet.parseIp6Packet(ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength())); break;
			case Ip6Packet.IPPROTO_UDP : list=new ArrayList<Packet>(); list.add(UdpPacket.parseUdpPacket(ip_pkt)); break;
			case Ip6Packet.IPPROTO_TCP : list=new ArrayList<Packet>(); list.add(TcpPacket.parseTcpPacket(ip_pkt)); break;
		}
		if (list==null) list=new ArrayList<Packet>();
		list.add(0,ip_pkt);
		return list;
	}

	
	/** Analyzes an Ethernet packet.
	  * @param eth_pkt the Ethernet packet */
	public static ProtocolField analyze(EthPacket eth_pkt) {
		ProtocolField field=new ProtocolField("Ethernet frame",eth_pkt.toString());
		Address src_addr=eth_pkt.getDestAddress();
		Address dst_addr=eth_pkt.getDestAddress();
		field.addSubField("dest-address",dst_addr!=null?dst_addr.toString():"none");
		field.addSubField("source-address",src_addr!=null?src_addr.toString():"none");
		int type=eth_pkt.getType();
		field.addSubField("type","0x"+Integer.toString(type,16));
		byte[] buf=eth_pkt.getPayloadBuffer();
		int off=eth_pkt.getPayloadOffset();
		int len=eth_pkt.getPayloadLength();
		switch (type) {
			case EthPacket.ETH_ARP : field.addSubField(analyze(ArpPacket.parseArpPacket(eth_pkt))); break;
			case EthPacket.ETH_IP4 : field.addSubField(analyze(Ip4Packet.parseIp4Packet(buf,off,len))); break;
			case EthPacket.ETH_IP6 : field.addSubField(analyze(Ip6Packet.parseIp6Packet(buf,off,len))); break;
			default : field.addSubField("payload",ByteUtils.asHex(buf,off,len));
		}	
		return field;
	}


	/** Analyzes a PPP packet.
	  * @param ppp_pkt the PPP packet */
	public static ProtocolField analyze(PppEncapsulation ppp_pkt) {
		ProtocolField field=new ProtocolField("PPP frame",ppp_pkt.toString());
		Address src_addr=ppp_pkt.getDestAddress();
		Address dst_addr=ppp_pkt.getDestAddress();
		field.addSubField("dest-address",dst_addr!=null?dst_addr.toString():"none");
		field.addSubField("source-address",src_addr!=null?src_addr.toString():"none");
		int type=ppp_pkt.getProtocol();
		field.addSubField("type","0x"+Integer.toString(type,16));
		byte[] buf=ppp_pkt.getPayloadBuffer();
		int off=ppp_pkt.getPayloadOffset();
		int len=ppp_pkt.getPayloadLength();
		switch (type) {
			case PppEncapsulation.TYPE_IP4 : field.addSubField(analyze(Ip4Packet.parseIp4Packet(buf,off,len))); break;
			case PppEncapsulation.TYPE_IP6 : field.addSubField(analyze(Ip6Packet.parseIp6Packet(buf,off,len))); break;
			default : field.addSubField("payload",ByteUtils.asHex(buf,off,len));
		}	
		return field;
	}

	/** Analyzes an ARP packet.
	  * @param arp_pkt the ARP packet */
	public static ProtocolField analyze(ArpPacket arp_pkt) {
		ProtocolField field=new ProtocolField("ARP packet",arp_pkt.toString());
		int operation=arp_pkt.getOperation();
		field.addSubField("operation",operation==ArpPacket.ARP_REQUEST?"request (1)":operation==ArpPacket.ARP_REPLY?"reply (2)":"unknown ("+operation+")");
		int htype=arp_pkt.getHtype();
		field.addSubField("hardware-type",htype==ArpPacket.HARDWARE_TYPE_ETH?"Ethernet (1)":String.valueOf(htype));
		int ptype=arp_pkt.getPtype();
		field.addSubField("protocol-type",htype==ArpPacket.PROTOCOL_TYPE_IP4?"IP (0x800)":"0x"+Integer.toHexString(ptype));
		field.addSubField("sha",""+arp_pkt.getSenderHardwareAddress());
		field.addSubField("tha",""+arp_pkt.getTargetHardwareAddress());
		field.addSubField("pha",""+arp_pkt.getSenderProtocolAddress());
		field.addSubField("pha",""+arp_pkt.getSenderProtocolAddress());
		return field;
	}

	/** Analyzes an IPv4 packet.
	  * @param ip_pkt the IPv4 packet */
	public static ProtocolField analyze(Ip4Packet ip_pkt) {
		ProtocolField field=new ProtocolField("IP packet",ip_pkt.toString());
		field.addSubField("version","4");
		field.addSubField("tos",String.valueOf(ip_pkt.getTOS()));
		field.addSubField("length",String.valueOf(ip_pkt.getPacketLength()));
		int id=ip_pkt.getID();
		int offset=ip_pkt.getFragmentOffset();
		boolean df=ip_pkt.getDontFragmentFlag();
		boolean mf=ip_pkt.getMoreFragmentsFlag();
		ProtocolField fragment_field=new ProtocolField("fragment",String.valueOf(id)+","+String.valueOf(offset));
		fragment_field.addSubField("fragment-offset",String.valueOf(offset));
		fragment_field.addSubField("dont-fragment",String.valueOf(df));
		fragment_field.addSubField("more-fragments",String.valueOf(mf));
		field.addSubField(fragment_field);
		field.addSubField("ttl",String.valueOf(ip_pkt.getTTL()));
		int ip_proto=ip_pkt.getProto();
		field.addSubField("proto",String.valueOf(ip_proto));
		field.addSubField("checksum","0x"+ByteUtils.intToTwoBytes((ip_pkt.getChecksum())));
		IpAddress src_addr=(IpAddress)ip_pkt.getSourceAddress();
		IpAddress dst_addr=(IpAddress)ip_pkt.getDestAddress();
		field.addSubField("source-address",""+src_addr);
		field.addSubField("dest-address",""+dst_addr);
		switch (ip_proto) {
			case Ip4Packet.IPPROTO_ICMP : field.addSubField(analyze(new IcmpMessage(ip_pkt))); break;
			case Ip4Packet.IPPROTO_UDP : field.addSubField(analyze(UdpPacket.parseUdpPacket(ip_pkt))); break;
			case Ip4Packet.IPPROTO_TCP : field.addSubField(analyze(TcpPacket.parseTcpPacket(ip_pkt))); break;
			default : field.addSubField("payload",ByteUtils.asHex(ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength()));
		}
		return field;
	}

	/** Analyzes an ICMP message.
	  * @param icmp_pkt the ICMP message */
	public static ProtocolField analyze(IcmpMessage icmp_pkt) {
		ProtocolField field=new ProtocolField("ICMP message",icmp_pkt.toString());
		// TODO
		return field;
	}

	/** Analyzes an IPv6 packet.
	  * @param ip_pkt the IPv6 packet */
	public static ProtocolField analyze(Ip6Packet ip_pkt) {
		ProtocolField field=new ProtocolField("IPv6 packet",ip_pkt.toString());
		// TODO
		return field;
	}

	/** Analyzes an ICMPv6 message.
	  * @param icmp_pkt the ICMPv6 message */
	public static ProtocolField analyze(Icmp6Message icmp_pkt) {
		ProtocolField field=new ProtocolField("ICMPv6 message",icmp_pkt.toString());
		// TODO
		return field;
	}

	/** Analyzes a UDP datagram.
	  * @param udp_pkt the UDP datagram */
	public static ProtocolField analyze(UdpPacket udp_pkt) {
		ProtocolField field=new ProtocolField("UDP datagram",udp_pkt.toString());
		// TODO
		return field;
	}

	/** Analyzes a TCP segment.
	  * @param tcp_pkt the TCP segment */
	public static ProtocolField analyze(TcpPacket tcp_pkt) {
		ProtocolField field=new ProtocolField("TCP segment",tcp_pkt.toString());
		// TODO
		return field;
	}

}
