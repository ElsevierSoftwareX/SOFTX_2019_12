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


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** Ethernet interface for sending or receiving Ethernet packets through a physical link.
 * <p>
 * The physical link can be either a point-to-point or broadcast link.
 */
public class EthInterface extends NetInterface {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}
	
	/** Ethernet address */
	//EthAddress eth_addr;

	/** Physical interface for sending and receiving raw packets */
	NetInterface ph_interface;

	/** This physical interface listener */
	NetInterfaceListener this_ph_listener;
	
	
	/** Creates a new Ethernet interface.
	 * @param ph_interface interface for sending and receiving raw packets through a physical link
	 * @param eth_addr the Ethernet address */
	public EthInterface(NetInterface ph_interface, EthAddress eth_addr) {
		super(eth_addr);
		this.ph_interface=ph_interface;
		addAddress(EthAddress.BROADCAST_ADDRESS);
		this_ph_listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				processIncomingPacket(ni,pkt);
			}
		};
		ph_interface.addListener(this_ph_listener);
	}

	
	@Override
	public void send(Packet pkt, Address dest_addr) {
		EthPacket eth_pkt=(EthPacket)pkt;
		if (eth_pkt.getSourceAddress()==null) eth_pkt.setSourceAddress(getAddresses()[0]);
		if (eth_pkt.getDestAddress()==null) eth_pkt.setDestAddress(dest_addr);
		if (DEBUG) debug("send(): Ethernet packet: "+eth_pkt);
		ph_interface.send(eth_pkt,null);
	}

	
	/** Processes an incoming Ethernet packet. */
	private void processIncomingPacket(NetInterface ni, Packet pkt) {
		EthPacket eth_pkt=EthPacket.parseEthPacket(pkt.getBytes());
		EthAddress dest_addr=(EthAddress)eth_pkt.getDestAddress();
		if (hasAddress(dest_addr)) {
			if (DEBUG) debug("processIncomingPacket(): Ethernet packet: "+eth_pkt);
			for (NetInterfaceListener li : getListeners()) {
				try { li.onIncomingPacket(this,eth_pkt); } catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}	

	
	@Override
	public void close() {
		ph_interface.removeListener(this_ph_listener);
		super.close();
	}	

}
