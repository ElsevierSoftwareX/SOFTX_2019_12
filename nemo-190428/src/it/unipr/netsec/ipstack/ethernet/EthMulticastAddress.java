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

package it.unipr.netsec.ipstack.ethernet;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip6.Ip6Address;


/** Ethernet multicast address.
 */
public class EthMulticastAddress extends EthAddress {

	/** Creates a new multicast address based on a multicast IPv4 address.
	 * Inserts the low 23 Bits of the multicast IPv4 Address into the Ethernet address.
	 * @param ip_addr the multicast IPv4 address */
	public EthMulticastAddress(Ip4Address ip_addr) {
		super(initIp4Bytes(ip_addr.getBytes()));
	}

	/** Initializes a byte array with a Ethernet multicast address based on a multicast IPv4 address.
	 * @param ip_addr the multicast IPv4 address */
	private static byte[] initIp4Bytes(byte[] ip_addr) {
		return new byte[]{(byte)0x01,(byte)0x00,(byte)0x5e,(byte)(ip_addr[1]&0x7f),ip_addr[2],ip_addr[3]};
	}

	
	/** Creates a new multicast address based on an multicast IPv6 address.
	 * Inserts the low 32 Bits of the multicast IPv6 Address into the Ethernet address.
	 * @param ip_addr the multicast IPv6 address */
	public EthMulticastAddress(Ip6Address ip_addr) {
		super(initIp6Bytes(ip_addr.getBytes()));
	}

	/** Initializes a byte array with a Ethernet multicast address based on a multicast IPv6 address.
	 * @param ip_addr the multicast IPv6 address */
	private static byte[] initIp6Bytes(byte[] ip_addr) {
		return new byte[]{(byte)0x33,(byte)0x33,ip_addr[12],ip_addr[13],ip_addr[14],ip_addr[15]};
	}

}
