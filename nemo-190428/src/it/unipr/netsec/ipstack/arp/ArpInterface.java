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


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;



/** ARP interface for sending and receiving ARP packets through an underling Ethernet interface.
 */
public class ArpInterface extends NetInterface {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** Ethernet interface */
	NetInterface eth_interface;

	/** This Ethernet listener */
	NetInterfaceListener this_eth_listener;

		
	
	/** Creates a new ARP interface.
	 * @param eth_interface the Ethernet interface */
	public ArpInterface(NetInterface eth_interface) {
		super(eth_interface.getAddresses());
		this.eth_interface=eth_interface;
		this_eth_listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				processIncomingPacket(ni,pkt);
			}
		};
		eth_interface.addListener(this_eth_listener);
	}

	
	@Override
	public void send(Packet pkt, Address dest_addr) {
		ArpPacket arp_pkt=(ArpPacket)pkt;
		if (DEBUG) debug("send(): ARP packet: "+arp_pkt);
		EthPacket eth_pkt=new EthPacket(getAddresses()[0],dest_addr,EthPacket.ETH_ARP,arp_pkt.getBytes());	
		eth_interface.send(eth_pkt,dest_addr);
	}

	
	/** Processes an incoming Ethernet packet. */
	private void processIncomingPacket(NetInterface ni, Packet pkt) {
		try {
			EthPacket eth_pkt=(EthPacket)pkt;
				if (eth_pkt.getType()==EthPacket.ETH_ARP) {
				ArpPacket arp_pkt=ArpPacket.parseArpPacket(eth_pkt);
				if (DEBUG) debug("processIncomingPacket(): ARP packet: "+arp_pkt);
				NetInterfaceListener[] ll=listeners.toArray(new NetInterfaceListener[0]);
				for (NetInterfaceListener li : ll) {
					try { li.onIncomingPacket(this,arp_pkt); } catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	
	@Override
	public void close() {
		eth_interface.removeListener(this_eth_listener);
		super.close();
	}	

}
