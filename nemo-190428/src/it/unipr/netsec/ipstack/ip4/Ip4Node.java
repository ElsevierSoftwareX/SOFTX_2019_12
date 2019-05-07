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

package it.unipr.netsec.ipstack.ip4;


import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpDestinationUnreachableMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoReplyMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoRequestMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpTimeExceededMessage;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** IPv4 node.
 * It includes ICMP support and IP routing function.
 * <p>
 * A routing table is automatically created based on the directly connected links and corresponding IP prefixes.
 * Use method {@link #getRoutingTable()} and method {@link it.unipr.netsec.ipstack.routing.RoutingTable#add(Route)} to add more routing entries.
 * <p>
 * Ip4Node can act as either a router or host, depending whether <i>IP forwarding</i> is enabled or not.
 * Use method {@link #setForwarding(boolean)} to enable IP forwarding function.
 */
public class Ip4Node extends Node {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Ip4Node.class.getSimpleName()+"["+getID()+"]: "+str);
	}

	/** Whether sending ICMP Destination Unreachable messages */
	boolean SEND_ICMP_DEST_UREACHABLE=false;
	
	/** Listener for incoming packets */
	Ip4NodeListener listener;


	/** Creates a new IP node.
	 * @param ip_interfaces set of IP network interfaces */
	public Ip4Node(NetInterface[] ip_interfaces) {
		super(ip_interfaces,new RoutingTable(),false);
		RoutingTable routing_table=getRoutingTable();
		for (NetInterface ni : ip_interfaces) {
			for (Address addr : ni.getAddresses()) {
				if (addr instanceof Ip4AddressPrefix) {
					// add limited broadcast address
					Ip4Prefix prefix=((Ip4AddressPrefix)addr).getPrefix();
					ni.addAddress(prefix.getSubnetBroadcastAddress());
					// add route
					routing_table.add(new Route(prefix,null,ni));
				}
			}
			// add broadcast and all-hosts addresses
			ni.addAddress(Ip4Address.ADDR_BROADCAST);
			ni.addAddress(Ip4Address.ADDR_ALL_HOSTS_MULTICAST);
		}
	}

	/** Sets incoming packet receiver.
	 * @param listener listener for incoming packets */
	public void setListener(Ip4NodeListener listener) {
		this.listener=listener;
	}

	/** Gets the routing table.
	 * @return routing table */
	public RoutingTable getRoutingTable() {
		return (RoutingTable)getRoutingFunction();
	}
	
	/** Gets a local IP address for sending datagrams to a target node.
	 * @param dst_addr address of the target node
	 * @return the IP address */
	public Ip4Address getSourceAddress(Address dst_addr) {
		Route route=getRoutingTable().getRoute(dst_addr);
		if (route!=null) return (Ip4Address)route.getOutputInterface().getAddresses()[0];
		else return null;
	}
	
	@Override
	protected void processReceivedPacket(NetInterface ni, Packet pkt) {
		if (DEBUG) debug("processReceivedPacket(): "+pkt);
		if (hasAddress(pkt.getDestAddress())) {
			Ip4Packet ip_pkt=(Ip4Packet)pkt;
			Integer proto=Integer.valueOf(ip_pkt.getProto());
			// process ICMP messages
			if (proto.intValue()==Ip4Packet.IPPROTO_ICMP) {
				IcmpMessage icmp_msg=new IcmpMessage(ip_pkt.getSourceAddress(),ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
				if (DEBUG) debug("processReceivedPacket(): ICMP message: "+icmp_msg);
				if (icmp_msg.getType()==IcmpMessage.TYPE_Echo_Request) {
					IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(icmp_msg);
					if (DEBUG) debug("processReceivedPacket(): ICMP Echo request from "+icmp_echo_request.getSourceAddress());
					IcmpEchoReplyMessage icmp_echo_reply=new IcmpEchoReplyMessage(icmp_echo_request.getDestAddress(),icmp_echo_request.getSourceAddress(),icmp_echo_request.getIdentifier(),icmp_echo_request.getSequenceNumber(),icmp_echo_request.getEchoData());
					sendPacket(icmp_echo_reply.toIp4Packet());
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
					if (SEND_ICMP_DEST_UREACHABLE) sendPacket(new IcmpDestinationUnreachableMessage(ip_pkt.getDestAddress(),ip_pkt.getSourceAddress(),IcmpDestinationUnreachableMessage.CODE_protocol_unreachable,ip_pkt).toIp4Packet());
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
		Ip4Packet ip_pkt=(Ip4Packet)pkt;
		Ip4Address dest_addr=(Ip4Address)ip_pkt.getDestAddress();
		//don't forward multicast packets
		if (dest_addr.isMulticast()) {
			if (DEBUG) debug("processForwardingPacket(): multicast packets are not forwarded");
			return;			
		}
		// else
		// decrement TTL and update checksum
		int ttl=ip_pkt.getTTL();
		if (ttl<=1) {
			if (DEBUG) debug("processForwardingPacket(): TTL<1, packet discarded");
			// send ICMP Time Exceeded
			Address dst_addr=ip_pkt.getSourceAddress();
			Address src_addr=getSourceAddress(dst_addr);
			sendPacket(new IcmpTimeExceededMessage(src_addr,dst_addr,IcmpTimeExceededMessage.CODE_time_to_live_exceeded_in_transit,ip_pkt).toIp4Packet());
			return;
		}
		// else	
		ip_pkt.setTTL(ttl-1);
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
