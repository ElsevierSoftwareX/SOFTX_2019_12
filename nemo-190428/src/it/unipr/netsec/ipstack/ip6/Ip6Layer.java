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


import it.unipr.netsec.ipstack.icmp4.IcmpLayer;
import it.unipr.netsec.ipstack.icmp6.Icmp6Layer;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6DestinationUnreachableMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.ip4.Ip4NodeListener;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;

import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** IPv6 layer provides standard IPv6 service to upper layers.
 * <p>
 * It includes basic ICMPv6 support.
 */
public class Ip6Layer {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}

	/** The layer listeners */
	Hashtable<Integer,Ip6LayerListener> listeners=new Hashtable<Integer,Ip6LayerListener>();

	//RoutingTable routing_table=new RoutingTable();

	/** IP node  */
	Ip6Node ip_node;

	/** ICMPv6 layer  */
	Icmp6Layer icmp_layer;

	
	/** Creates a new IP layer.
	 * @param ip_interfaces set of IP network interfaces */
	public Ip6Layer(NetInterface[] ip_interfaces) {
		ip_node=new Ip6Node(ip_interfaces);
		ip_node.setListener(new Ip6NodeListener(){
			@Override
			public void onIncomingPacket(Ip6Node ip_node, Ip6Packet ip_pkt) {
				processIncomingPacket(ip_pkt);
			}
		});
		ip_node.setForwarding(false);
		icmp_layer=new Icmp6Layer(this);
	}
	
	/** Creates a new IP layer.
	 * @param ip_node IP node */
	public Ip6Layer(Ip6Node ip_node) {
		this.ip_node=ip_node;
		ip_node.setListener(new Ip6NodeListener() {
			@Override
			public void onIncomingPacket(Ip6Node ip_node, Ip6Packet ip_pkt) {
				processIncomingPacket(ip_pkt);
			}
		});
		icmp_layer=new Icmp6Layer(this);
	}

	/** Sets the listener for a given protocol number.
	 * @param proto the protocol number
	 * @param listener the new listener for the given protocol number */
	public void setListener(int proto, Ip6LayerListener listener) {
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
	public void removeListener(Ip6LayerListener listener) {
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
	
	/** Gets the ICMP6 layer.
	 * @return the ICMP6 layer used by this IPv6 layer */
	public Icmp6Layer getIcmp6Layer() {
		return icmp_layer;
	}

	/** Sets forwarding mode.
	 * @param forwarding <i>true</i> for acting as relay node, <i>false</i> for acting as terminal node. */
	public void setForwarding(boolean forwarding) {
		ip_node.setForwarding(forwarding);
	}
	
	/** Gets a local IP address for sending datagrams to a target node.
	 * @param dst_addr address of the target node */
	public Ip6Address getSourceAddress(Address dst_addr) {
		Route route=getRoutingTable().getRoute(dst_addr);
		if (route!=null) return (Ip6Address)route.getOutputInterface().getAddresses()[0];
		else return null;
	}
	
	/** Sends an IP packet.
	 * @param pkt the packet to be sent */
	public void send(Ip6Packet pkt) {
		if (DEBUG) debug("send(): "+pkt);
		ip_node.sendPacket(pkt);
	}
	
	/** Processes an incoming packet.
	 * @param ip_pkt the packet */
	protected void processIncomingPacket(Ip6Packet ip_pkt) {
		// process IPv6 extension headers
		// TODO
		Integer proto=Integer.valueOf(ip_pkt.getPayloadType());
		if (listeners.containsKey(proto)) {
			if (DEBUG) debug("processIncomingPacket(): "+ip_pkt);
			listeners.get(proto).onReceivedPacket(this,ip_pkt);
		}
		else {
			if (proto.intValue()==Ip6Packet.IPPROTO_ICMP6) {
				// re-connect the default ICMP implementation
				icmp_layer.close();
				icmp_layer=new Icmp6Layer(this);
				listeners.get(proto).onReceivedPacket(this,ip_pkt);
			}
			else {
				// packet discarded
				// sends Destination (protocol) Unreachable ICMP message
				icmp_layer.send(new Icmp6DestinationUnreachableMessage((Ip6Address)ip_pkt.getDestAddress(),(Ip6Address)ip_pkt.getSourceAddress(),Icmp6DestinationUnreachableMessage.CODE_Address_unreachable,ip_pkt));
			}
		}
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName()+'['+(ip_node.getNetInterfaces().length==0? "flying-node" : ip_node.getNetInterfaces()[0].getAddresses()[0].toString())+']';
	}

}
