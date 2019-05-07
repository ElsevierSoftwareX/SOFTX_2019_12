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

package it.unipr.netsec.ipstack.icmp6;


import it.unipr.netsec.ipstack.ip6.Ip6Address;


/** IPv6 Solicited-Node multicast address.
 * <p>
 * A Solicited-Node multicast address is created by taking the last 24 bits of a unicast or anycast address and appending them to the prefix ff02::1:ff00:0/104.
 */
public class SolicitedNodeMulticastAddress extends Ip6Address {

	/** Creates a new address.
	 * @param ip_addr the unicast or anycast used for creating the Solicited-Node multicast address */
	public SolicitedNodeMulticastAddress(Ip6Address ip_addr) {
		super(initBytes(ip_addr.getBytes()));
	}

	
	/** Initializes a byte array with a Solicited-Node multicast address.
	 * @param ip_addr the unicast or anycast used for creating the Solicited-Node multicast address */
	private static byte[] initBytes(byte[] ip_addr) {
		return new byte[]{(byte)0xff,0x02,0,0,0,0,0,0,0,0,0,1,(byte)0xff,ip_addr[13],ip_addr[14],ip_addr[15]};
	}
	
}
