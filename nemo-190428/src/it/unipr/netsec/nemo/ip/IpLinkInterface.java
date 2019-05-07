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


import it.unipr.netsec.ipstack.icmp6.SolicitedNodeMulticastAddress;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.nemo.link.DataLinkInterface;


/** An IPv4 link interface.
 */
public class IpLinkInterface extends DataLinkInterface {

	/** Creates a new interface.
	 * The interface address and prefix length are dynamically obtained from the link
	 * through the method {@link IpLink#nextAddressPrefix()}.
	 * @param link the link to be attached to */
	public IpLinkInterface(IpLink link) {
		this(link,link.nextAddressPrefix());
	}
		
	/** Creates a new interface.
	 * The interface address and prefix length are dynamically obtained from the link
	 * through the method {@link IpLink#nextAddressPrefix()}.
	 * @param link the link to be attached to
	 * @param ip_addr the IP address */
	public IpLinkInterface(IpLink link, IpAddress ip_addr) {
		super(link,ip_addr);
		if (ip_addr instanceof Ip4Address) {
			addAddress(Ip4Address.ADDR_BROADCAST);
			addAddress(Ip4Address.ADDR_ALL_HOSTS_MULTICAST);
			if (ip_addr instanceof Ip4AddressPrefix) addAddress(((Ip4AddressPrefix)ip_addr).getPrefix().getSubnetBroadcastAddress());
		}
		else
		if (ip_addr instanceof Ip6Address) {
			addAddress(Ip6Address.ADDR_ALL_HOSTS_INTERFACE_MULTICAST);
			addAddress(Ip6Address.ADDR_ALL_HOSTS_LINK_MULTICAST);
			Ip6Address sn_m_addr=new SolicitedNodeMulticastAddress((Ip6Address)ip_addr);
			addAddress(sn_m_addr);		
		}
	}
		
	/** Creates an array of link interfaces.
	 * @param links an array of links
	 * @return the new link interfaces */
	public static IpLinkInterface[] createLinkInterfaceArray(IpLink[] links) {
		IpLinkInterface[] interfaces=new IpLinkInterface[links.length];
		for (int i=0; i<interfaces.length; i++) interfaces[i]=new IpLinkInterface(links[i]);
		return interfaces;
	}
	
}
