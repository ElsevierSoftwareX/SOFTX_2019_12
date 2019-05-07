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
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;

import it.unipr.netsec.ipstack.link.LinkInterface;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;


/** A generic link providing one-to-many delivery service.
 * <p>
 * The link has a finite bit-rate and a given propagation medium_delay.
 * The finite bit-rate must be taken into account before sending the packet.
 * <p>
 * If the propagation delay is greater than zero, the packet is delayed accordingly, before being passed to the target interface.
 */
public class DataLink extends it.unipr.netsec.ipstack.link.Link {

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,DataLink.class,str);
	}

	
	/** DataLink bit rate */
	long bit_rate=0;
	
	/** Medium delay [nanosecs] */
	//long medium_delay=0;

	/** Link delay function */
	DataLinkDelay link_delay;

	/** Link error function */
	DataLinkError link_error;

	/** Creates a new link. */
	public DataLink() {
	}
	
	/** Creates a new link.
	 * @param bit_rate bit rate */
	public DataLink(long bit_rate) {
		this(bit_rate,0);
	}
	
	/** Creates a new link.
	 * @param bit_rate bit rate
	 * @param medium_delay fixed medium delay in nanosecs */
	public DataLink(long bit_rate, final long medium_delay) {
		this.bit_rate=bit_rate;
		//this.medium_delay=medium_delay;
		link_delay=new DataLinkDelay() {
			@Override
			public long getPacketDelay(Packet pkt) {
				return medium_delay;
			}
		};
	}
	
	/** Gets the link bit rate.
	 * @return the bit rate */
	public long getBitRate() {
		return bit_rate;
	}
	
	/** Sets link delay.
	 * @param link_delay the delay function */
	public void setLinkDelay(DataLinkDelay link_delay) {
		this.link_delay=link_delay;
	}
	
	/** Sets link error.
	 * @param link_error the error function */
	public void setLinkError(DataLinkError link_error) {
		this.link_error=link_error;
	}
	
	@Override
	public void addLinkInterface(LinkInterface ni) {
		if (!(ni instanceof DataLinkInterface)) throw new RuntimeException("Only "+DataLinkInterface.class.getSimpleName()+" can be attached to a "+DataLink.class.getSimpleName());
		// else
		super.addLinkInterface(ni);
	}
	
	@Override
	public void transmit(Packet pkt, final LinkInterface src_ni, final Address dst_ni_addr) {
		if (link_error!=null) pkt=link_error.getPacketError(pkt);
		if (pkt==null) {
			if (DEBUG) debug("transmit(): link erorr: packet discarded");
		}
		else {
			long medium_delay=link_delay!=null? link_delay.getPacketDelay(pkt) : 0;
			if (medium_delay>0) {
				final Packet pkt_copy=(Packet)pkt.clone();
				TimerListener timer_listener=new TimerListener() {
					public void onTimeout(Timer t) {
						if (DEBUG) debug("transmit(): onTimeout(): transmission completed");
						DataLink.super.transmit(pkt_copy,src_ni,dst_ni_addr);
					}
				};
				Timer timer=Clock.getDefaultClock().newTimer(medium_delay/1000000,(int)(medium_delay%1000000),timer_listener);
				timer.start();		
			}
			else {
				DataLink.super.transmit(pkt,src_ni,dst_ni_addr);
			}			
		}
	}

}
