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

package it.unipr.netsec.ipstack.arp;


import it.unipr.netsec.ipstack.ethernet.EthAddress;


/** An ARP table entry.
 * Maintains the mapping between an IPv4 address and corresponding Data-Link address.
 */
public class ArpRecord {

	/** IPv4 address */
	//Ip4Address ip_addr;
	
	/** Data-Link address */
	EthAddress addr;
	
	/** Date of this mapping */
	long time;
	
	
	/** Creates a new ARP entry.
	 * @param addr Data-Link address
	 * @param time date of this mapping in milliscs */
	public ArpRecord(EthAddress addr, long time) {
		this.addr=addr;
		this.time=time;
	}


	/** Gets the IP address
	 * @return the IP address */
	/*public Ip4Address getIpAddress() {
		return ip_addr;
	}*/

	
	/** Gets the Data-Link address
	 * @return the Data-Link address */
	public EthAddress getAddress() {
		return addr;
	}


	/** Gets the date of this mappling.
	 * @return the time in millisecs */
	public long getTime() {
		return time;
	}

}
