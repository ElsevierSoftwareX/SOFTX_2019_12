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

package it.unipr.netsec.ipstack.net;



/** A loopback interface.
 * <p>
 * Sent packets are passed back to the interface listeners.
 */
public class LoopbackInterface extends NetInterface {

	/** Creates a new interface.
	 * @param addr interface address */
	public LoopbackInterface(Address addr) {
		super(addr);
	}

	
	/** Creates a new interface.
	 * @param addrs interface addresses */
	public LoopbackInterface(Address[] addrs) {
		super(addrs);
	}

	
	/** Sends a packet.
	 * @param dest_addr the address of the destination interface */
	public void send(Packet pkt, Address dest_addr) {
		for (NetInterfaceListener li : getListeners()) {
			try { li.onIncomingPacket(this,pkt); } catch (Exception e) {
				e.printStackTrace();
			}
		}		
	}

}
