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


import it.unipr.netsec.ipstack.icmp4.IcmpLayer;
import it.unipr.netsec.ipstack.icmp4.message.IcmpDestinationUnreachableMessage;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;

import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** IPv4 layer provides standard IPv4 service to upper layers.
 * <p>
 * It includes ICMP support.
 */
public class Ip4Layer {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}

	/** Whether sending ICMP Destination Unreachable messages */
	boolean SEND_ICMP_DEST_UREACHABLE=false;

	/** The layer listeners */
	Hashtable<Integer,Ip4LayerListener> listeners=new Hashtable<Integer,Ip4LayerListener>();

	//RoutingTable routing_table=new RoutingTable();

	/** IP node  */
	Ip4Node ip_node;

	/** ICMP layer  */
	IcmpLayer icmp_layer;


	/** Creates a new IP layer.
	 * @param ip_interfaces set of IP network interfaces */
	public Ip4Layer(NetInterface[] ip_interfaces) {
		ip_node=new Ip4Node(ip_interfaces);
		ip_node.setListener(new Ip4NodeListener() {
			@Override
			public void onIncomingPacket(Ip4Node ip_node, Ip4Packet ip_pkt) {
				processIncomingPacket(ip_pkt);
			}
		});
		ip_node.setForwarding(false);
		icmp_layer=new IcmpLayer(this);
	}

	/** Creates a new IP layer.
	 * @param ip_node IP node */
	public Ip4Layer(Ip4Node ip_node) {
		this.ip_node=ip_node;
		ip_node.setListener(new Ip4NodeListener() {
			@Override
			public void onIncomingPacket(Ip4Node ip_node, Ip4Packet ip_pkt) {
				processIncomingPacket(ip_pkt);
			}
		});
		icmp_layer=new IcmpLayer(this);
	}

	/** Sets the listener for a given protocol number.
	 * @param proto the protocol number
	 * @param listener the new listener for the given protocol number */
	public void setListener(int proto, Ip4LayerListener listener) {
		synchronized (listeners) {
			Integer key=Integer.valueOf(proto);
			if (listeners.containsKey(key)) listeners.remove(key);
			listeners.put(key,listener);
		}
	}
	
	/** Removes the listener for a given protocol number.
	 * @param proto the protocol number */
	public void removeListener(int proto) {
		synchronized (listeners) {
			Integer key=Integer.valueOf(proto);
			listeners.remove(key);
		}
	}
	
	/** Removes a listener.
	 * @param listener the listener to be removed */
	public void removeListener(Ip4LayerListener listener) {
		for (Integer key : listeners.keySet()) {
			if (listeners.get(key)==listener) {
				listeners.remove(key);
				break;
			}
		}
	}
	
	/** Gets the routing table.
	 * @return routing table */
	public RoutingTable getRoutingTable() {
		return (RoutingTable)ip_node.getRoutingFunction();
	}
	
	/** Gets the network interfaces.
	 * @return network interfaces */
	public NetInterface[] getNetInterfaces() {
		return ip_node.getNetInterfaces();
	}
	
	/** Gets the ICMP layer.
	 * @return the ICMP layer used by this IP layer */
	public IcmpLayer getIcmpLayer() {
		return icmp_layer;
	}
	
	/** Sets forwarding mode.
	 * @param forwarding <i>true</i> for acting as relay node, <i>false</i> for acting as terminal node. */
	public void setForwarding(boolean forwarding) {
		ip_node.setForwarding(forwarding);
	}
	
	/** Gets a local IP address for sending datagrams to a target node.
	 * @param dst_addr address of the target node
	 * @return the IP address */
	public Ip4Address getSourceAddress(Address dst_addr) {
		if (((Ip4Address)dst_addr).isMulticast()) return (Ip4Address)getNetInterfaces()[0].getAddresses()[0];
		// else
		Route route=getRoutingTable().getRoute(dst_addr);
		if (route!=null) return (Ip4Address)route.getOutputInterface().getAddresses()[0];
		else return null;
	}
	
	/** Sends an IP packet.
	 * @param pkt the packet to be sent */
	public void send(Ip4Packet pkt) {
		if (DEBUG) debug("send(): "+pkt);
		IpAddress dest_addr=(IpAddress)pkt.getDestAddress();
		if (dest_addr.isMulticast()) {
			for (NetInterface ni: ip_node.getNetInterfaces()) {
				if (DEBUG) debug("sendPacket(): forwarding packet through interface "+ni+" to "+dest_addr);
				ni.send(pkt,dest_addr);	
			}			
		}
		else ip_node.sendPacket(pkt);
	}
	
	/** Processes an incoming packet.
	 * @param pkt the packet */
	private void processIncomingPacket(Ip4Packet ip_pkt) {
		Integer proto=Integer.valueOf(ip_pkt.getProto());
		if (listeners.containsKey(proto)) {
			if (DEBUG) debug("processIncomingPacket(): "+ip_pkt);
			listeners.get(proto).onReceivedPacket(this,ip_pkt);
		}
		else {
			if (proto.intValue()==Ip4Packet.IPPROTO_ICMP) {
				// re-connect the default ICMP implementation
				icmp_layer.close();
				icmp_layer=new IcmpLayer(this);
				listeners.get(proto).onReceivedPacket(this,ip_pkt);
			}
			else {
				// packet discarded
				// sends Destination (protocol) Unreachable ICMP message
				if (SEND_ICMP_DEST_UREACHABLE) icmp_layer.send(new IcmpDestinationUnreachableMessage(ip_pkt.getDestAddress(),ip_pkt.getSourceAddress(),IcmpDestinationUnreachableMessage.CODE_protocol_unreachable,ip_pkt));
			}
		}
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName()+'['+(ip_node.getNetInterfaces().length==0? "flying-node" : ip_node.getNetInterfaces()[0].getAddresses()[0].toString())+']';
	}

}
