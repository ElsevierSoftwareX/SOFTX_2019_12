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


import java.util.ArrayList;

import org.zoolu.util.Clock;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;

import it.unipr.netsec.ipstack.link.Link;
import it.unipr.netsec.ipstack.link.LinkInterface;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** Generic {@link it.unipr.netsec.ipstack.link.LinkInterface link interface} attached to a {@link DataLink link} with with a finite bit-rate.
 */
public class DataLinkInterface extends LinkInterface {

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,DataLinkInterface.class.getSimpleName()+"["+getId()+"]: "+str);
	}

	
	/** Sender buffer */
	ArrayList<LinkPacket> buffer=new ArrayList<LinkPacket>();

	/** Whether the interface is transmitting a packet */
	boolean transmitting=false;
	
	
	/** Creates a new interface.
	 * @param link the link to be attached to */
	public DataLinkInterface(DataLink link) {
		super(link);
	}
	
	/** Creates a new interface.
	 * @param link the link to be attached to
	 * @param name interface name */
	public DataLinkInterface(DataLink link, String name) {
		super(link,name);
	}
	
	/** Creates a new interface.
	 * @param link the link to be attached to
	 * @param addr the interface address */
	public DataLinkInterface(DataLink link, Address addr) {
		super(link,addr);
	}
	
	/** Creates a new interface.
	 * @param link the link to be attached to
	 * @param addresses the interface addresses */
	public DataLinkInterface(Link link, Address[] addresses) {
		super(link,addresses);
	}
	
	@Override
	public void send(Packet pkt, Address dest_addr) {
		if (DEBUG) debug("send(): sending "+pkt.getPacketLength()+" bytes to "+dest_addr);
		if (((DataLink)link).getBitRate()<=0) {
			link.transmit(pkt,this,dest_addr);
		}
		else {
			synchronized (buffer) {
				buffer.add(new LinkPacket((Packet)pkt.clone(),dest_addr));
				if (DEBUG) debug("send(): queued packet "+buffer.size());
				if (!transmitting) {
					if (buffer.size()>1) new RuntimeException("Bug found: link with a queued-packet is not in 'transmit' state");
					transmitHOL();
				}
			}
		}
	}
	
	/** Transmits the packet head of line of the output buffer.
	 * It waits the time for transmitting the entire packet (TX time = (packet_length * 8 bit) / bit_rate)
	 * and passes it to the link for being delivered to the destination interfaces. */
	private void transmitHOL() {
		long transmit_nanosecs=Math.round(buffer.get(0).getPacket().getPacketLength()*8*1000000000.0D/((DataLink)link).getBitRate());
		transmitting=true;
		if (DEBUG) debug("transmitHOL(): transmit_time: "+transmit_nanosecs);
		TimerListener timer_listener=new TimerListener() {
			@Override
			public void onTimeout(Timer t) {
				if (DEBUG) debug("onTimeout(): transmission completed");
				synchronized (buffer) {
					LinkPacket link_pkt=buffer.get(0);
					buffer.remove(0);
					link.transmit(link_pkt.getPacket(),DataLinkInterface.this,link_pkt.getDestAddress());
					if (buffer.size()>0) transmitHOL();
					else transmitting=false;
				}				
			}
		};
		Timer timer=Clock.getDefaultClock().newTimer(transmit_nanosecs/1000000,(int)(transmit_nanosecs%1000000),timer_listener);
		timer.start();		
	}
	
	/** Processes an incoming packet.
	 * @param link the input link
	 * @param pkt the packet */
	public void processIncomingPacket(DataLink link, Packet pkt) {
		if (!running) return;
		// else
		if (DEBUG) debug("processIncomingPacket(): received "+pkt.getPacketLength()+" bytes");
		for (NetInterfaceListener li : getListeners())  li.onIncomingPacket(this,pkt);
	}
	
	@Override
	public void close() {
		link.removeLinkInterface(this);
		running=false;
		super.close();
	}

	
	/** A buffered packet. */
	class LinkPacket {
		Packet pkt;
		Address dst_addr;
		
		public LinkPacket(Packet pkt,Address dst_addr) {
			this.pkt=pkt;
			this.dst_addr=dst_addr;
		}
		public Packet getPacket() {
			return pkt;
		}
		public Address getDestAddress() {
			return dst_addr;
		}
	}

}
