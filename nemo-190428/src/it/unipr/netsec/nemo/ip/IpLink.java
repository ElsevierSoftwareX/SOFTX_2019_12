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

package it.unipr.netsec.nemo.ip;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpAddressPrefix;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.nemo.link.DataLink;

import java.util.ArrayList;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** An IP link.
 * It extends {@link it.unipr.netsec.nemo.link.DataLink} by providing methods for
 * dynamic IP configuration and router discovery.
 */
public class IpLink extends DataLink {
	
	/** Debug mode */
	public static boolean DEBUG=false;


/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,IpLink.class,str);
	}

	
	/** Network prefix */
	protected IpPrefix prefix;
	
	/** Router list */
	protected ArrayList<IpAddress> routers=new ArrayList<IpAddress>();

	/** Address sequence number */
	byte[] sqn;

	
	/** Creates a new link.
	 * @param prefix network prefix */
	public IpLink(IpPrefix prefix) {
		super();
		this.prefix=prefix;
		sqn=new byte[prefix.prefixAddress().length()];
	}
	
	/** Creates a new link.
	 * @param bit_rate bit rate
	 * @param prefix network prefix */
	public IpLink(long bit_rate, IpPrefix prefix) {
		super(bit_rate);
		this.prefix=prefix;
		sqn=new byte[prefix.prefixAddress().length()];
	}
	
	/** Gets network prefix.
	 * @return network prefix */
	public IpPrefix getPrefix() {
		return prefix;
	}
	
	/** Adds a router.
	 * @param router router address */
	public void addRouter(IpAddress router) {
		synchronized (routers) {
			routers.add(router);
		}
	}
	
	/** Removes a router.
	 * @param router address of the router to be removed */
	public void removeRouter(IpAddress router) {
		synchronized (routers) { 
			for (int i=0; i<routers.size(); i++) {
				IpAddress addr=routers.get(i);
				if (addr.equals(router)) {
					routers.remove(i);
				}
			}
		}
	}

	/** Gets all routers.
	 * @return array of router addresses */
	public IpAddress[] getRouters() {
		synchronized (routers) { 
			return routers.toArray(new IpAddress[]{});
		}
	}
	
	/** Gets a new IP address and prefix length. */
	public synchronized IpAddressPrefix nextAddressPrefix() {
		ByteUtils.inc(sqn);
		byte[] addr=ByteUtils.copy(prefix.getBytes());
		byte[] mask=prefix.prefixMask();
		for (int i=0; i<addr.length; i++) addr[i]|=(mask[i]^0xff)&sqn[i];
		IpAddress ip_addr;
		if (prefix instanceof Ip4Prefix) {
			ip_addr=new Ip4Address(addr);
			if (ip_addr.equals(((Ip4Prefix)prefix).getSubnetBroadcastAddress())) {
				if (DEBUG) debug("nextAddressPrefix(): skip broadcast address: "+ip_addr);
				return nextAddressPrefix();
			}			
		} else {
			ip_addr=new Ip6Address(addr);
		}
		if (ip_addr.equals(prefix.prefixAddress())) {
			if (DEBUG) debug("nextAddressPrefix(): skip network address: "+ip_addr);
			return nextAddressPrefix();
		}
		if (DEBUG) debug("nextAddressPrefix(): "+ip_addr);
		if (ip_addr instanceof Ip4Address) return new Ip4AddressPrefix((Ip4Address)ip_addr,prefix.prefixLength());			
		else return new Ip6AddressPrefix((Ip6Address)ip_addr,prefix.prefixLength());
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName()+'['+prefix.toString()+']';
	}
}
