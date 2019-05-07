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

package it.unipr.netsec.tuntap;


import java.io.IOException;

import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** IPv4 interface for sending and receiving IPv4 packets through an underling
 * TUN/TAPinterface.
 */
public class Ip4TuntapInterface extends NetInterface {
	
	/** The actual TUN or TAP interface */
	NetInterface tuntap;
	
	
	/** Creates a new interface.
	 * @param name name of the interface (e.g. "tun0" or "tap0"). if <i>null</i>, a new TAP interface is added
	 * @throws IOException */
	public Ip4TuntapInterface(String name, Ip4AddressPrefix ip_addr_prefix) throws IOException {
		super(ip_addr_prefix);
		if (name==null || name.toLowerCase().startsWith("tap")) {
			//System.out.println("Ip4TuntapInterface: TAP interface");
			tuntap=new Ip4TapInterface(name,ip_addr_prefix);
		}
		else
		if (name.toLowerCase().startsWith("tun") || name.toLowerCase().startsWith("utun")) {
			//System.out.println("Ip4TuntapInterface: TUN interface");
			tuntap=new Ip4TunInterface(name,ip_addr_prefix);
		}
		else throw new IOException("Unrecognized TUN/TAP interface type: "+name);
		
		tuntap.addListener(new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				for (NetInterfaceListener li : getListeners()) {
					try { li.onIncomingPacket(Ip4TuntapInterface.this,pkt); } catch (Exception e) {
						e.printStackTrace();
					}
				}
			}			
		});
	}

	@Override
	public boolean hasAddress(Address addr) {
		return tuntap.hasAddress(addr);
	}

	@Override
	public void addAddress(Address addr) {
		tuntap.addAddress(addr);
	}

	@Override
	public void removeAddress(Address addr) {
		tuntap.removeAddress(addr);
	}

	@Override
	public Address[] getAddresses() {
		return tuntap.getAddresses();
	}

	@Override
	public void send(final Packet pkt, final Address dest_addr) {
		tuntap.send(pkt,dest_addr);
	}

	@Override
	public void close() {
		tuntap.close();
	}	

}
