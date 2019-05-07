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

package it.unipr.netsec.ipstack.icmp6.message.option;


import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.net.Address;


/** ICMP6 Link-Layer Address option.
 * It is a generic option that contain an address.
 */
public abstract class LinkLayerAddressOption extends Icmp6Option {
		
	/** Creates a new ICMP6 option.
	 * @param o the ICMPv6 option */
	protected LinkLayerAddressOption(Icmp6Option o) {
		super(o);
	}

	/** Creates a new ICMP6 option.
	 * @param type the option type
	 * @param addr the address */
	protected LinkLayerAddressOption(int type, Address addr) {
		super(type,addr.getBytes());
	}

	/** Parses an ICMP6 option.
	 * @param buf buffer containing the option */
	/*protected static LinkLayerAddressOption parseOption(byte[] buf) {
		return parseOption(buf,0);
	}*/

	/** Parses an ICMP6 option.
	 * @param buf buffer containing the option
	 * @param off the offset within the buffer */
	/*protected static LinkLayerAddressOption parseOption(byte[] buf, int off) {
		return new LinkLayerAddressOption(Icmp6Option.parseOption(buf,off));
	}*/
	
	/** Gets the Link-Layer Address.
	 * @return the address */ 
	 public EthAddress getLinkLayerAddress() {
		 return new EthAddress(buf,off);
	 }
	 
}
