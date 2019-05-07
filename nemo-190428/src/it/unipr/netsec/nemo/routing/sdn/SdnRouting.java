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

package it.unipr.netsec.nemo.routing.sdn;


import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.nemo.routing.LinkStateInfo;
import it.unipr.netsec.nemo.routing.NetworkMap;
import it.unipr.netsec.nemo.routing.RouteInfo;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.DynamicRouting;
import it.unipr.netsec.nemo.routing.DynamicRoutingInterface;
import it.unipr.netsec.nemo.routing.graph.Graph;

import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** Centralized implementation of a SPF (Shortest Path First) algorithm.
 * <p>
 * It collects DataLink State information from all nodes and builds the corresponding network graph.
 * It uses the network graph for computing the shortest path toward all possible destinations from any connected node.
 */
public class SdnRouting implements DynamicRouting {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private static void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,SdnRouting.class,str);
	}

	
	/** Network map */
	NetworkMap network_map;

	/** Interfaces for dynamic routing configuration (node address -> routing interface) */
	Hashtable<Address,DynamicRoutingInterface> routing_interfaces=new Hashtable<>();

	
	/** Creates a new dynamic routing.
	 * @param algo shortest-path algorithm */ 
	public SdnRouting(ShortestPathAlgorithm algo) {
		network_map=new NetworkMap(algo);
	}
	
	/** Gets the network graph.
	 * @return the network graph */
	public Graph getNetworkGraph() {
		return network_map.getNetworkGraph();
	}

	/** Updates the routing table of a node.
	 * @param addr address of the node of which the routing table will be updated */
	public void update(Address addr) {
		routing_interfaces.get(addr).updateRouting(network_map.getRoutes(addr));
	}
	
	/** Updates routing tables of all nodes. */
	public void updateAllNodes() {
		for (Address addr: routing_interfaces.keySet()) {
			update(addr);
		}
	}
	
	@Override
	public void connect(Address node_addr, LinkStateInfo[] lsa, DynamicRoutingInterface routing_interface) {
		if (DEBUG) debug("connect("+node_addr+"): "+lsa);
		routing_interfaces.put(node_addr,routing_interface);
		network_map.addLikState(node_addr,lsa);
	}
	
	@Override
	public void disconnect(Address node_addr) {
		routing_interfaces.remove(node_addr);
		network_map.removeLinkState(node_addr);
	}
	
	@Override
	public Packet processReceivedPacket(Address node_addr, Packet pkt) {
		// nothing to do
		return pkt;
	}

}
