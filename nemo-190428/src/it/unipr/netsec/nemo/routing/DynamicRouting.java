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

package it.unipr.netsec.nemo.routing;


import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;


/** Generic routing mechanism, that is able to dynamically compute the routes toward all possible destinations.
 * It can be either a centralized system (e.g. SDN controller) or a distributed routing protocol (like OSPF or RIP).
 * <p>
 * Any node can contribute to the routing mechanism by providing local routing information ({@link LinkStateInfo Link-State information})
 * when connecting to the routing mechanism through the method {@link #connect(Address, LinkStateInfo[], DynamicRoutingInterface)}.
 * It is up to the implemented routing mechanism how the provided routing information is used to compute all routes.
 * <p>
 * Distance-Vector and Link-State routing protocols, as well as Software Defined Networking mechanisms, are possible implementations.
 */
public interface DynamicRouting {

	/** Connects a node to the routing mechanism.
	 * @param node_addr the node address
	 * @param lsa array of link state info of the node
	 * @param routing_interface the routing interface of the node */
	public void connect(Address node_addr, LinkStateInfo[] lsa, DynamicRoutingInterface routing_interface);
	
	/** Disconnects a node from the routing mechanism.
	 * @param node_addr the node address */
	public void disconnect(Address node_addr);
	
	/** When a node receives a new packet.
	 * @param node_addr the node address
	 * @param pkt the received packet
	 * @return the original packet (if not processed by the routing mechanism) or <i>null</i> */
	public Packet processReceivedPacket(Address node_addr, Packet pkt);
	
	
}
