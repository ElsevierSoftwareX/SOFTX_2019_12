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
import it.unipr.netsec.ipstack.net.NetAddress;



/** DataLink state advertisement.
 */
public class LinkStateInfo {

	/** Interface address */
	Address addr;  
	
	/** DataLink address */
	NetAddress prefix;
	
	/** DataLink cost */
	int cost;
	
	
	/** Creates a new link state info.
	 * @param addr the interface address
	 * @param prefix link address
	 * @param cost link cost */
	public LinkStateInfo(Address addr, NetAddress prefix, int cost) {
		this.addr=addr;
		this.prefix=prefix;
		this.cost=cost;
	}

	/** Gets the interface address.
	 * @return the address */
	public Address getAddress() {
		return addr;
	}

	/** Gets the link address.
	 * @return the address */
	public NetAddress getPrefix() {
		return prefix;
	}

	/** Gets the link cost.
	 * @return the cost */
	public int getCost() {
		return cost;
	}
	
	@Override
	public String toString() {
		return "addr="+addr+";prefix="+prefix+";cost="+cost;
	}
	
}
