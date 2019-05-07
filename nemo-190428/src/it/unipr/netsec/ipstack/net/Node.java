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

package it.unipr.netsec.ipstack.net;


import java.util.ArrayList;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingFunction;


/** A generic network node.
 * It may have one or more network interfaces and one routing function. <br>
 * It may act either as terminal node or intermediate relay node,
 * depending on the value of the 'forwarding' attribute.
 * <p>
 * Incoming packets are processed by two different methods depending whether
 * the incoming packet is for this node or not.
 */
public class Node {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Node.class.getSimpleName()+"["+getID()+"]: "+str);
	}

	
	/** Network interfaces */
	protected ArrayList<NetInterface> net_interfaces=new ArrayList<NetInterface>();
	
	/** Routing function */
	protected RoutingFunction routing_function;
	
	/** Packet forwarding */
	protected boolean forwarding;

	/** Network interface listener */
	protected NetInterfaceListener this_ni_listener;
	

	
	/** Creates a new node. */
	/*public Node() {
		this(null,null,false);
	}*/
	
	/** Creates a new node.
	 * @param net_interfaces network interfaces
	 * @param routing_function the routing function
	 * @param forwarding whether acting as relay node; <i>true</i> for relay node, <i>false</i> for terminal node. */
	public Node(NetInterface[] net_interfaces, RoutingFunction routing_function, boolean forwarding) {
		this.routing_function=routing_function;
		this.forwarding=forwarding;
		this_ni_listener=new NetInterfaceListener() {
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				processReceivedPacket(ni,pkt);
			}
		};
		if (net_interfaces!=null) {
			for (NetInterface ni : net_interfaces) addNetInterface(ni);
		}
	}
	
	/** Adds a network interface.
	 * @param ni the network interface */
	public void addNetInterface(NetInterface ni) {
		ni.addListener(this_ni_listener);
		net_interfaces.add(ni);
	}
	
	/** Removes a network interface.
	 * @param ni the network interface */
	public void removeNetInterface(NetInterface ni) {
		ni.removeListener(this_ni_listener);
		ni.close();
		net_interfaces.remove(ni);
	}	
	
	/** Sets routing function.
	 * @param routing_function the routing function */
	public void setRouting(RoutingFunction routing_function) {
		this.routing_function=routing_function;
	}
	
	/** Gets the routing function.
	 * @return the routing function of this node*/
	public RoutingFunction getRoutingFunction() {
		return routing_function;
	}
	
	/** Sets forwarding mode.
	 * @param forwarding whether acting as relay node; <i>true</i> for relay node, <i>false</i> for terminal node. */
	public void setForwarding(boolean forwarding) {
		this.forwarding=forwarding;
	}
	
	/** Gets all network interfaces.
	 * @return the list of network interfaces */
	public NetInterface[] getNetInterfaces() {
		return net_interfaces.toArray(new NetInterface[]{});
	}
	
	/** Whether a given address targets this node.
	 * @param addr the address
	 * @return <i>true</i> if the address targets this node; <i>false</i> otherwise */
	public boolean hasAddress(Address addr) {
		for (NetInterface ni : net_interfaces) if (ni.hasAddress(addr)) return true;
		// else
		return false;
	}
	
	/** Sends a packet.
	 * @param pkt the packet to be sent */
	public void sendPacket(Packet pkt) {
		//if (DEBUG) debug("sendPacket(): "+ByteUtils.bytesToHexString(pkt.getBytes()));
		if (DEBUG) debug("sendPacket(): "+pkt);
		if (routing_function==null) throw new RuntimeException("No routing function as been set for this node.");
		Route route=routing_function.getRoute(pkt.getDestAddress());
		if (route!=null) {
			Address next_hop=route.getNextHop();
			if (next_hop==null) next_hop=pkt.getDestAddress();
			NetInterface out_interface=route.getOutputInterface();
			/*if (out_interface==null && next_hop!=null)
				for (NetInterface ni : link_interfaces)
					if (ni.getLink().findAddress(next_hop)) { out_interface=ni; break; }*/
			if (DEBUG) debug("sendPacket(): forwarding packet through interface "+out_interface+" to next node "+next_hop);
			if (out_interface!=null) out_interface.send(pkt,next_hop);
		}
		else {
			if (DEBUG) debug("sendPacket(): WARNING: no route to "+pkt.getDestAddress());
		}
	}
	
	/** Processes incoming packet received by a network interface.
	 * @param ni the input network interface
	 * @param pkt the packet */
	protected void processReceivedPacket(NetInterface ni, Packet pkt) {
		//if (DEBUG) debug("processPacket(): "+ByteUtils.bytesToHexString(pkt.getBytes()));
		if (DEBUG) debug("processIncomingPacket(): "+pkt);
		Address dest_addr=pkt.getDestAddress();
		if (!hasAddress(dest_addr)) {
			// packet forwarding
			if (forwarding) {		
				processForwardingPacket(pkt);
			}
		}
	}
	
	/** Processes a packet that has to be forwarded.
	 * @param pkt the packet to be forwarded */
	protected void processForwardingPacket(Packet pkt) {
		sendPacket(pkt);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName()+'['+getID()+']';
	}

	/** Gets an Identifier for this node.
	 * It is used by the {@link #toString()} method.
	 * @return the identifier */
	protected String getID() {
		return net_interfaces.size()==0? "null" : net_interfaces.get(0).getAddresses()[0].toString();
	}

}
