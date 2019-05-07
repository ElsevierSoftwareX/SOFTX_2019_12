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
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** IPv4 interface for sending and receiving IPv4 packets through a TUN interface.
 */
public class Ip4TunInterface extends NetInterface {
	
	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** Sender buffer */
	private byte[] send_buffer=new byte[Ip4Packet.MAXIMUM_PACKET_SIZE+2];

	/** Receiver buffer */
	private byte[] recv_buffer=new byte[Ip4Packet.MAXIMUM_PACKET_SIZE+2];

	/** TUN interface */
	TuntapSocket tun;

	/** Whether it is running */
	boolean is_running=true;	

	
	/** Creates a new IP interface.
	 * @param name name of the TUN interface (e.g. "tun0"); if <i>null</i>, a new interface is added
	 * @param ip_addr the IP address and prefix length 
	 * @throws IOException */
	public Ip4TunInterface(String name, Ip4AddressPrefix ip_addr) throws IOException {
		super(ip_addr);
		tun=new TuntapSocket(TuntapSocket.Type.TUN,name);
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
		Ip4Packet ip_pkt=(Ip4Packet)pkt;
		TunPacket tun_pkt=new TunPacket(ip_pkt);
		synchronized (send_buffer) {
			int len=tun_pkt.getBytes(send_buffer,0);
			try {
				tun.send(send_buffer,0,len);
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
					int len=tun.receive(recv_buffer,0);
					if (is_running) {
						TunPacket tun_pkt=new TunPacket(recv_buffer,0,len);
						Ip4Packet ip_pkt=Ip4Packet.parseIp4Packet(tun_pkt.getPayload());
						//if (DEBUG) debug("receiver(): packet: "+ip_pkt.toString());
						if (DEBUG) debug("receiver(): packet: "+ProtocolAnalyzer.exploreInner(ip_pkt).toString());
						for (NetInterfaceListener li : getListeners()) {
							try { li.onIncomingPacket(this,ip_pkt); } catch (Exception e) {
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
