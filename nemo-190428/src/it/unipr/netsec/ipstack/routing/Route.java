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

package it.unipr.netsec.ipstack.routing;


import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetAddress;
import it.unipr.netsec.ipstack.net.NetInterface;


/** An entry of a Routing Table.
 * It is formed by a possible destination address or destination prefix, the address of the next-hop node, and the output interface.
 */
public class Route {	
	
	/** Destination network address */
	NetAddress dest_naddr;

	/** Next hop */
	Address next_hop;

	/** Output interface */
	NetInterface out_interface;

	
	
	/** Creates a new RT entry.
	 * @param dest_naddr the destination network address
	 * @param next_hop the next-hop router
	 * @param out_interface the output network interface */
	public Route(NetAddress dest_naddr, Address next_hop, NetInterface out_interface) {
		this.dest_naddr=dest_naddr;
		this.next_hop=next_hop;
		this.out_interface=out_interface;
	}

	
	/** Gets the destination network address.
	 * @return the network address */
	public NetAddress getDestNetAddress() {
		return dest_naddr;
	}


	/** Gets the next hop node
	 * @return the next hop */
	public Address getNextHop() {
		return next_hop;
	}


	/** Gets the output network interface
	 * @return the output interface */
	public NetInterface getOutputInterface() {
		return out_interface;
	}
	
	
	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append("dest=").append(dest_naddr!=null? dest_naddr.toString() : null).append(',');
		sb.append("next-hop=").append(next_hop!=null? next_hop.toString() : null).append(',');
		sb.append("interface=").append(out_interface!=null? out_interface.toString() : null);
		return sb.toString();
	}

	
	/** Gets a JSON representation of this object.
	 * @return the JSON object */
	/*public JSONObject toJson() {
		JSONObject json=new JSONObject();
		json.put("dest",dest_naddr!=null? dest_naddr.toString() : null);
		json.put("next-hop",next_hop!=null? next_hop.toString() : null);
		json.put("interface",out_interface!=null? out_interface.toString() : null);
		return json;
	}*/
	
}
