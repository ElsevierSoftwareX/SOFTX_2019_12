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



/** DataLink state advertisement.
 */
public class RouteInfo {

	/** Destination address */
	String dest;
	
	/** Next hop */
	String next_hop;
	
	/** Interface address */
	String interface_addr;  
	
	/** Path cost */
	int cost;
	
	
	/** Creates a new link state info.
	 * @param dest destination address
	 * @param next_hop next hop
	 * @param interface_addr interface address
	 * @param cost link cost */
	public RouteInfo(String dest, String next_hop, String interface_addr, int cost) {
		this.dest=dest;
		this.next_hop=next_hop;
		this.interface_addr=interface_addr;
		this.cost=cost;
	}

	/** Gets the  destination address.
	 * @return the address */
	public String getDestination() {
		return dest;
	}

	/** Gets the next hop address.
	 * @return the address */
	public String getNextHop() {
		return next_hop;
	}

	/** Gets the interface address.
	 * @return the interface address */
	public String getInterfaceAddress() {
		return interface_addr;
	}

	/** Gets the path cost.
	 * @return the cost */
	public int getCost() {
		return cost;
	}
	
	@Override
	public String toString() {
		return "dest="+dest+";via="+next_hop+";if="+interface_addr+";cost="+cost;
	}
}
