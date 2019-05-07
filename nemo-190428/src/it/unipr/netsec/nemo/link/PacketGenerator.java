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

package it.unipr.netsec.nemo.link;


import org.zoolu.util.Clock;
import org.zoolu.util.Logger;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;

import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** A pair of IP nodes attached to two links.
 * It can can be used for generating packets from the first node (<i>sender</i>) to the second node (<i>target</i>).
. */
public class PacketGenerator extends DataLinkInterface {

	public static boolean DEBUG=false;
	
	private void log(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}
	

	// SENDER
	
	/** Packet */
	Packet pkt;

	/** Transmission target interface */
	Address dst_addr;

	/** Number of packets */
	long num;
	
	/** Hop limit (TTL) */
	int hop_limit;
	
	/** Transmission counter */
	long tx_count;
	
	/** Packet transmission time in nanoseconds */
	long pkt_time;

	/** Inter-packet time in nanoseconds */
	long inter_time;

	/** Start time in nanoseconds */
	long start_time;

	/** Virtual start time in nanoseconds */
	long virtual_start_time;


	// RECEIVER
	
	/** Receiver interface */
	DataLinkInterface dst_interface;

	/** Receiver counter */
	long rx_count;
	
	/** Number of hops of the last received packet */
	int hop_num;
	
	/** Virtual time [microsecs] of the last received packet */
	long virtual_time=0;

	/** Real time [microsecs] of the last received packet */
	long real_time=0;

	final Object lock=new Object();
	
	/** Receiver listener */
	PacketGenerator.Listener listener=null;

	
	/** Creates a new packet generator.
	 * @param tx_link the link where the generator sender is attached to
	 * @param tx_addr the interface address of the sender */
	public PacketGenerator(DataLink tx_link, Address tx_addr) {
		super(tx_link,tx_addr);
		if (DEBUG) log("TX: "+tx_link+", "+tx_addr);
	}
	
	/** Creates a new packet generator.
	 * @param tx_link the link where the generator sender is attached to
	 * @param tx_addr the interface address of the sender
	 * @param rx_link the link where the generator receiver is attached to
	 * @param rx_addr the interface address of the receiver */
	public PacketGenerator(DataLink tx_link, Address tx_addr, DataLink rx_link, Address rx_addr) {
		this(tx_link,tx_addr);
		dst_interface=new DataLinkInterface(rx_link, rx_addr);
		dst_interface.addListener(new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				rx_count++;				
				virtual_time=(Clock.getDefaultClock().nanoTime()-virtual_start_time)/1000;
				real_time=(System.nanoTime()-start_time)/1000;
				hop_num=hop_limit+1-(pkt instanceof Ip6Packet? ((Ip6Packet)pkt).getHopLimit() : ((Ip4Packet)pkt).getTTL()); 
				if (listener!=null) {
					listener.onReceivedPacket(PacketGenerator.this,rx_count,pkt.getPacketLength(),hop_num,virtual_time,real_time);
				}
				if (rx_count==num) {
					if (DEBUG) {
						log("Last RX packet: "+pkt.toString());
						log("Virtual time: "+virtual_time+"us");
						log("Real time: "+real_time+"ms");
					}
					synchronized (lock) {
						lock.notifyAll();
					}
				}
			}			
		});
		if (DEBUG) log("RX: "+rx_link+", "+rx_addr);
	}
	
	/** Sends a number of packets.
	 * @param pkt the packet to be sent
	 * @param dst_addr the destination interface
	 * @param num the number of packets
	 * @param inter_millisec the time to wait between the end of a transmission and the begin of the next one, in milliseconds
	 * @param listener listener of the packet generator */
	public void send(Packet pkt, Address dst_addr, long num, long inter_millisec, PacketGenerator.Listener listener) {
		this.listener=listener;
		if (DEBUG) {
			log("Number of packets: "+num);
			log("Inter-packet time: "+inter_millisec+"ms");
			log("First TX packet: "+pkt.toString());
		}
		this.pkt=pkt;
		this.dst_addr=dst_addr;
		this.num=num;
		this.inter_time=inter_millisec*1000000;
		long bit_rate=link instanceof DataLink? ((DataLink)link).getBitRate() : 0;
		pkt_time=bit_rate>0? Math.round(pkt.getPacketLength()*8*1000000000.0/bit_rate) : 0;
		tx_count=0;
		rx_count=0;
		hop_limit=pkt instanceof Ip6Packet? ((Ip6Packet)pkt).getHopLimit() : ((Ip4Packet)pkt).getTTL(); 
		start_time=System.nanoTime();
		virtual_start_time=Clock.getDefaultClock().nanoTime();
		if (pkt_time+inter_time>0) {
			transmitPackets(true);
			try {
					synchronized (lock) {
						lock.wait();
					}
			}
			catch (Exception e) {}
		}
		else {
			for ( ; tx_count<num; tx_count++) {
				link.transmit((Packet)pkt.clone(),PacketGenerator.this,dst_addr);
			}
		}
	}
	
	/** Transmits the packets taking into account the packet length and the link bit rate. */
	private void transmitPackets(boolean first) {
		long transmit_time_nanosecs=pkt_time+(first? 0 : inter_time);
		TimerListener timer_listener=new TimerListener() {
			@Override
			public void onTimeout(Timer t) {
				synchronized (pkt) {
					link.transmit((Packet)pkt.clone(),PacketGenerator.this,dst_addr);
					if (++tx_count<num) transmitPackets(false);
				}				
			}
		};
		Timer timer=Clock.getDefaultClock().newTimer(transmit_time_nanosecs/1000000,(int)(transmit_time_nanosecs%1000000),timer_listener);
		timer.start();		
	}
	
	
	/** Gets the number of sent packets.
	 * @return number of sent packets */
	public long getTxCount() {
		return tx_count;
	}

	/** Gets the number of received packets.
	 * @return number of received packets */
	public long getRxCount() {
		return rx_count;
	}

	/** Gets the number of hops of the last received packet.
	 * @return number of hops */
	public int getHopNumber() {
		return hop_num;
	}

	/** Gets the virtual time of the last received packet.
	 * @return the virtual time in microseconds */
	public long getVirtualTime() {
		return virtual_time;
	}
	
	/** Gets the real time of the last received packet.
	 * @return the real time in microseconds */
	public long getRealTime() {
		return real_time;
	}
	
	
	/** Packet generator listener.
	 * It listens for the reception of the last packet.
	 */
	public interface Listener {

		/** When a packet is received.
		 * @param pg the packet generator
		 * @param pkt_sqn sequence number of the packet
		 * @param pkt_len packet length
		 * @param hop_num number of hops
		 * @param virtual_time end-to-end virtual time in nanoseconds
		 * @param real_time end-to-end real time in microseconds */
		public void onReceivedPacket(PacketGenerator pg, long pkt_sqn, int pkt_len, int hop_num, long virtual_time, long real_time);
	}
	
}
