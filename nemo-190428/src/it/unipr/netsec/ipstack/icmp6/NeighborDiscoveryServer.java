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


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6NeighborAdvertisementMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6NeighborSolicitationMessage;
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;
import it.unipr.netsec.ipstack.icmp6.message.option.TargetLinkLayerAddressOption;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6EthInterface;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/**  Neighbor Discovery server.
 * It responds to Neighbor Discovery requests.
 */
public class NeighborDiscoveryServer {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** IP interface */
	Ip6EthInterface ip_interface;

	/** Server IPv6 address */
	Ip6Address ip_addr;

	/** Server Ethernet address */
	EthAddress eth_addr;

	/** Listener for incoming IP packets */ 
	NetInterfaceListener this_ip_listener;
	
	

	/** Creates a new Neighbor Discovery server.
	 * @param ip_interface the IP interface
	 * @param ip_addr the IP address
	 * @param eth_addr the Ethernet address */
	public NeighborDiscoveryServer(Ip6EthInterface ip_interface, Ip6Address ip_addr, EthAddress eth_addr) {
		this.ip_interface=ip_interface;
		this.ip_addr=ip_addr;
		this.eth_addr=eth_addr;
		this_ip_listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				processIncomingPacket(ni,pkt);
			}
		};
		ip_interface.addListener(this_ip_listener);
	}

	
	/** Processes an incoming IP packet. */
	protected void processIncomingPacket(NetInterface ni, Packet pkt) {
		Ip6Packet ip_pkt=(Ip6Packet)pkt;
		if (ip_pkt.getPayloadType()==Ip6Packet.IPPROTO_ICMP6) {
			if (DEBUG) debug("processIncomingPacket(): received ICMPv6 packet");
			Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
			int icmp_type=icmp_msg.getType();
			if (icmp_type==Icmp6Message.TYPE_Neighbor_Solicitation) {
				Icmp6NeighborSolicitationMessage neighbor_solicitation=new Icmp6NeighborSolicitationMessage(icmp_msg);
				if (neighbor_solicitation.getTargetAddress().equals(ip_addr)) {
					Ip6Address remote_ip_addr=(Ip6Address)icmp_msg.getSourceAddress();
					if (DEBUG) debug("processIncomingPacket(): received ICMP6 Neighbor Solicitation: who-has "+ip_addr+"? tell "+remote_ip_addr);
					Icmp6Option[] options=new Icmp6Option[]{new TargetLinkLayerAddressOption(eth_addr)};
				    Icmp6NeighborAdvertisementMessage neighbor_advertisement=new Icmp6NeighborAdvertisementMessage(ip_addr,(Ip6Address)neighbor_solicitation.getSourceAddress(),false,true,true,ip_addr,options);
					ip_interface.send(neighbor_advertisement.toIp6Packet(),remote_ip_addr);
					if (DEBUG) debug("processIncomingPacket(): sent ICMP6 Neighbor Advertisement: "+ip_addr+" is-at "+eth_addr);
				}
			}
		}
	}

	
	/** Closes the server. */ 
	public void close() {
		ip_interface.removeListener(this_ip_listener);
	}	

}
