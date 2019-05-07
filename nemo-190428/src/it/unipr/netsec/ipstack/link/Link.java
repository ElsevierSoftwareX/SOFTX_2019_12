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

package it.unipr.netsec.ipstack.link;


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;

import java.util.HashSet;
import java.util.Set;


/** A generic link providing one-to-many delivery service.
 * It may connect any number of attached {@link LinkInterface link interfaces}.
 */
public class Link {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,Link.class,str);
	}

	
	/** Active interfaces attached to this link */
	Set<LinkInterface> link_interfaces=new HashSet<LinkInterface>();

	
	/** Creates a new link. */
	public Link() {
	}
	
	/** Adds a link interface.
	 * @param ni the interface to be added */
	public void addLinkInterface(LinkInterface ni) {
		link_interfaces.add(ni);
	}
	
	/** Removes an interface.
	 * @param ni the interface to be removed */
	public void removeLinkInterface(LinkInterface ni) {
		link_interfaces.remove(ni);
	}
	
	/** Gets the number of attached interfaces.
	 * @return number of interfaces */
	public int numberOfInterfaces() {
		return link_interfaces.size();
	}
	
	/** Whether a given address is present on this link.
	 * @param addr the target address
	 * @return <i>true</i> if the address is present */
	public boolean findAddress(Address addr) {
		for (LinkInterface ni : link_interfaces) {
			if (ni.hasAddress(addr)) return true;
		}
		return false;
	}
	
	/** Transmits a packet to a target interface.
	 * @param pkt the packet to be sent
	 * @param src_ni the source link interface, used for sending the packet
	 * @param dst_ni_addr the address of the destination link interface */
	public void transmit(Packet pkt, final LinkInterface src_ni, final Address dst_ni_addr) {
		//if (DEBUG) debug("transmit(): attached interfaces: "+link_interfaces.size());
		boolean success=false;
		for (LinkInterface ni : link_interfaces) {
			if (ni!=src_ni) {
				if (dst_ni_addr==null || ni.hasAddress(dst_ni_addr)) {
					if (DEBUG) debug("transmit(): packet passed to "+ni);
					ni.processIncomingPacket(this,pkt);
					success=true;
				}
				else {
					if (DEBUG) debug("transmit(): packet NOT passed to "+ni);
				}
			}
		}
		if (!success) {
			if (DEBUG) debug("transmit(): no destination interface found");
		}
	}
	
	/*@Override
	public String toString() {
		return id;
	}*/

}
