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

package it.unipr.netsec.ipstack.ip6;


import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.icmp6.SolicitedNodeMulticastAddress;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6DestinationUnreachableMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoReplyMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoRequestMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6TimeExceededMessage;
import it.unipr.netsec.ipstack.ip4.Ip4NodeListener;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpAddressPrefix;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.exthdr.ExtensionHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.RoutingHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.SegmentRoutingHeader;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** IPv6 node.
 * It includes ICMP support and IP routing function.
 * <p>
 * A routing table is automatically created based on the directly connected links and corresponding IP prefixes.
 * Use method {@link #getRoutingTable()} and method {@link it.unipr.netsec.ipstack.routing.RoutingTable#add(Route)} to add more routing entries.
 * <p>
 * Ip6Node can act as either a router or host, depending whether <i>IP forwarding</i> is enabled or not.
 * Use method {@link #setForwarding(boolean)} to enable IP forwarding function.
 */
public class Ip6Node extends Node {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Ip6Node.class.getSimpleName()+"["+getID()+"]: "+str);
	}

	/** Listener for incoming packets */
	Ip6NodeListener listener;

	
	/** Creates a new IP node.
	 * @param ip_interfaces set of IP network interfaces */
	public Ip6Node(NetInterface[] ip_interfaces) {
		super(ip_interfaces,new RoutingTable(),false);
		RoutingTable routing_table=getRoutingTable();
		for (NetInterface ni : ip_interfaces) {
			for (Address addr : ni.getAddresses()) {
				if (addr instanceof Ip6AddressPrefix) {
					Ip6AddressPrefix ip_addr=(Ip6AddressPrefix)addr;
					Ip6Address sn_m_addr=new SolicitedNodeMulticastAddress(ip_addr);
					ni.addAddress(sn_m_addr);
					IpPrefix prefix=ip_addr.getPrefix();
					routing_table.add(new Route(prefix,null,ni));					
				}
			}
			ni.addAddress(Ip6Address.ADDR_ALL_HOSTS_INTERFACE_MULTICAST);
			ni.addAddress(Ip6Address.ADDR_ALL_HOSTS_LINK_MULTICAST);
		}
	}
	
	/** Sets incoming packet receiver.
	 * @param listener listener for incoming packets */
	public void setListener(Ip6NodeListener listener) {
		this.listener=listener;
	}

	/** Gets the routing table.
	 * @return routing table */
	public RoutingTable getRoutingTable() {
		return (RoutingTable)getRoutingFunction();
	}
	
	/** Gets a local IP address for sending datagrams to a target node.
	 * @param dst_addr address of the target node */
	public Ip6Address getSourceAddress(Address dst_addr) {
		Route route=getRoutingTable().getRoute(dst_addr);
		if (route!=null) return (Ip6Address)route.getOutputInterface().getAddresses()[0];
		else return null;
	}
	
	@Override
	protected void processReceivedPacket(NetInterface ni, Packet pkt) {
		if (DEBUG) debug("processReceivedPacket(): "+pkt);
		Ip6Packet ip_pkt=(Ip6Packet)pkt;
		// process IPv6 extension headers
		// TODO
		Address dest_addr=pkt.getDestAddress();
		if (hasAddress(dest_addr)) {
			// process routing header
			if (forwarding && ip_pkt.hasExtHdr(ExtensionHeader.ROUTING_HDR)) {
				//debug(local_addrs[0]+": packet has RH");
				RoutingHeader rh=new RoutingHeader(ip_pkt.getExtHdr(ExtensionHeader.ROUTING_HDR));
				if (rh.getRoutingType()==RoutingHeader.TYPE_SRH) {
					debug("packet has SRH");
					SegmentRoutingHeader srh=new SegmentRoutingHeader(rh);
					int segment_left=srh.getSegmentLeft();
					if (segment_left>0) {
						debug("there are more segments");
						srh.setSegmentLeft(--segment_left);
						dest_addr=srh.getSegmentAt(segment_left);
						ip_pkt.setDestAddress(dest_addr);
						if (segment_left==0) {
							// IF Clean-up bit is set THEN remove the SRH
							debug("last segment");
							if (srh.getCleanupFlag()) {
								debug("clean-up");
								ip_pkt.removeExtHdr(ExtensionHeader.ROUTING_HDR);
							}
						}
						// forward the packet
						processForwardingPacket(ip_pkt);
					}
					else {
						// give the packet to the next PID (application)
						debug("end of segments");
					}
				}
				return;
			}
			
			// process other extension headers
			// TODO
			
			// process payload
			Integer proto=Integer.valueOf(ip_pkt.getPayloadType());
			if (proto.intValue()==Ip6Packet.IPPROTO_ICMP6) {
				Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
				if (DEBUG) debug("processReceivedPacket(): ICMP message: "+icmp_msg);
				if (icmp_msg.getType()==Icmp6Message.TYPE_Echo_Request) {
					Icmp6EchoRequestMessage icmp_echo_request=new Icmp6EchoRequestMessage(icmp_msg);
					if (DEBUG) debug("processReceivedPacket(): ICMPv6 Echo request from "+icmp_echo_request.getSourceAddress());
					Icmp6EchoReplyMessage icmp_echo_reply=new Icmp6EchoReplyMessage((Ip6Address)icmp_echo_request.getDestAddress(),(Ip6Address)icmp_echo_request.getSourceAddress(),icmp_echo_request.getIdentifier(),icmp_echo_request.getSequenceNumber(),icmp_echo_request.getEchoData());
					sendPacket(icmp_echo_reply.toIp6Packet());
				}
				else {
					// process other ICMP messages
					if (listener!=null) listener.onIncomingPacket(this,ip_pkt);
				}
			}
			else {
				// process non-ICMP packets
				if (listener!=null) listener.onIncomingPacket(this,ip_pkt);
				else {
					// packet discarded
					// sends Destination (protocol) Unreachable ICMP message
					sendPacket(new Icmp6DestinationUnreachableMessage((Ip6Address)ip_pkt.getDestAddress(),(Ip6Address)ip_pkt.getSourceAddress(),Icmp6DestinationUnreachableMessage.CODE_Address_unreachable,ip_pkt).toIp6Packet());
				}
			}
		}
		else {
			// packet forwarding
			if (forwarding) {
				processForwardingPacket(pkt);
			}
		}
	}
	
	@Override
	protected void processForwardingPacket(Packet pkt) {
		if (DEBUG) debug("processForwardingPacket(): "+pkt);
		Ip6Packet ip_pkt=(Ip6Packet)pkt;
		//don't forward multicast packets
		if (((IpAddress)ip_pkt.getDestAddress()).isMulticast()) {
			if (DEBUG) debug("processForwardingPacket(): multicast packets are not forwarded");
			return;			
		}
		// else
		// decrement hop_limit
		int hop_limit=ip_pkt.getHopLimit();
		if (hop_limit<=1) {
			if (DEBUG) debug("processForwardingPacket(): hop_limit<1, packet discarded");
			// send ICMP Time Exceeded
			Ip6Address dst_addr=(Ip6Address)ip_pkt.getSourceAddress();
			Ip6Address src_addr=getSourceAddress(dst_addr);
			sendPacket(new Icmp6TimeExceededMessage(src_addr,dst_addr,Icmp6TimeExceededMessage.CODE_time_to_live_exceeded_in_transit,ip_pkt).toIp6Packet());
			return;						
		}
		// else
		ip_pkt.setHopLimit(hop_limit-1);
		// process IPv6 Hop-By-Hop Options header
		// TODO
		sendPacket(ip_pkt);
	}

	@Override
	public void sendPacket(Packet pkt) {
		if (DEBUG) debug("sendPacket(): "+pkt);
		IpAddress dest_addr=(IpAddress)pkt.getDestAddress();
		if (dest_addr.isMulticast()) {
			for (NetInterface ni: net_interfaces) {
				if (DEBUG) debug("sendPacket(): forwarding packet through interface "+ni+" to "+dest_addr);
				ni.send(pkt,dest_addr);	
			}			
		}
		else super.sendPacket(pkt);
	}

}
