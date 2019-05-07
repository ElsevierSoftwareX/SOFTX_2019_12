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

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.analyzer.ProtocolAnalyzer;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** TAP interface for sending or receiving Ethernet packets through a TAP interface.
 */
public class TapInterface extends NetInterface {
	
	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** Sender buffer */
	private byte[] send_buffer=new byte[EthPacket.MAXIMUM_PAYLOAD_SIZE+18]; // MTU + 14B ETH-HDR + 4B IEEE802.1Q-TAG

	/** Receiver buffer */
	private byte[] recv_buffer=new byte[EthPacket.MAXIMUM_PAYLOAD_SIZE+18]; // MTU + 14B ETH-HDR + 4B IEEE802.1Q-TAG

	/** TAP interface */
	TuntapSocket tap;
	
	/** Whether it is running */
	boolean is_running=true;	

	
	/** Creates a new TAP interface.
	 * @param name name of the TAP interface (e.g. "tap0"); if <i>null</i>, a new interface is added
	 * @throws IOException */
	public TapInterface(String name) throws IOException {
		super((Address)null);
		tap=new TuntapSocket(TuntapSocket.Type.TAP,name);
		new Thread() {
			public void run() {
				receiver();
			}
		}.start();
	}

	
	@Override
	public void send(Packet pkt, Address dest_addr) {
		//if (DEBUG) debug("send(): packet: "+pkt.toString());
		if (DEBUG) debug("send(): packet: "+ProtocolAnalyzer.exploreInner(pkt).toString());
		synchronized (send_buffer) {
			int len=pkt.getBytes(send_buffer,0);
			try {
				tap.send(send_buffer,0,len);
			}
			catch (IOException e) {
				if (DEBUG) debug(e.toString());
			}
		}
	}
	
	
	/** Receives packets. */
	private void receiver() {
		synchronized (recv_buffer) {
			while (is_running) {
				try {				
					int len=tap.receive(recv_buffer,0);
					if (is_running) {
						EthPacket eth_pkt=EthPacket.parseEthPacket(recv_buffer,0,len);
						//if (DEBUG) debug("receiver(): packet: "+eth_pkt.toString());
						if (DEBUG) debug("receiver(): packet: "+ProtocolAnalyzer.exploreInner(eth_pkt).toString());
						for (NetInterfaceListener li : getListeners()) {
							try { li.onIncomingPacket(this,eth_pkt); } catch (Exception e) {
								e.printStackTrace();
							}
						}
					}
				}
				catch (IOException e) {
					if (DEBUG) debug(e.toString());
				}
			}
		}
	}

	
	@Override
	public void close() {
		is_running=false;
		super.close();
	}

}
