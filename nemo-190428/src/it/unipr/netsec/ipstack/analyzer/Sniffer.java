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

package it.unipr.netsec.ipstack.analyzer;


import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.rawsocket.ethernet.RawEthInterface;


/** It captures packets on one or more network interfaces.
 * <p>
 * For each capture packet the method {@link SnifferListener#onPacket(Sniffer, NetInterface, Packet)} is called.
 */
public class Sniffer {
	
	/** Network interfaces */
	NetInterface[] net_interfaces;
	
	/** Network interface listener */
	NetInterfaceListener ni_listener;
	
	/** Sniffer listener */
	SnifferListener listener;
	
	
	/** Creates a packet sniffer.
	 *  The sniffer is attached to a network interface.
	 * @param net_interface the network interface where attaching the sniffer */
	public Sniffer(NetInterface net_interface, SnifferListener listener) {
		this(new NetInterface[] {net_interface},listener);
	}
	
	/** Creates a packet sniffer.
	 *  The sniffer is attached to one or more network interfaces.
	 * @param net_interfaces network interfaces where attaching the sniffer */
	public Sniffer(NetInterface[] net_interfaces, SnifferListener listener) {
		this.listener=listener;
		NetInterfaceListener ni_listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				Sniffer.this.listener.onPacket(Sniffer.this,ni,pkt);
			}
		};
		for (NetInterface ni : net_interfaces) {
			if (ni instanceof RawEthInterface) ((RawEthInterface)ni).addPromiscuousListener(ni_listener);
			else ni.addListener(ni_listener);
		}
	}
	
	/** Closes the sniffer. */
	public void close() {
		for (NetInterface ni : net_interfaces) {
			if (ni instanceof RawEthInterface) ((RawEthInterface)ni).removePromiscuousListener(ni_listener);
			else ni.removeListener(ni_listener);
		}
	}
	
}
