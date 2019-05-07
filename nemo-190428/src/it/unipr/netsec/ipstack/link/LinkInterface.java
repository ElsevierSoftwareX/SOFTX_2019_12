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

package it.unipr.netsec.ipstack.link;


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.analyzer.ProtocolAnalyzer;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;


/** A generic link interface.
 * <p>
 * It allows the sending and receiving of packets through a {@link Link}.
 */
public class LinkInterface extends NetInterface {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,LinkInterface.class.getSimpleName()+"["+getId()+"]: "+str);
	}

	
	/** Link */
	protected Link link;
	
	/** Whether the interface is running */
	protected boolean running;
	
	
	/** Creates a new interface.
	 * @param link the link to be attached to */
	public LinkInterface(Link link) {
		super((Address)null);
		init(link);
	}
	
	/** Creates a new interface.
	 * @param link the link to be attached to
	 * @param name interface name */
	public LinkInterface(Link link, String name) {
		super(name);
		init(link);
	}
	
	/** Creates a new interface.
	 * @param link the link to be attached to
	 * @param addr the interface address */
	public LinkInterface(Link link, Address addr) {
		super(addr);
		init(link);
	}
	
	/** Creates a new interface.
	 * @param link the link to be attached to
	 * @param addresses the interface addresses */
	public LinkInterface(Link link, Address[] addresses) {
		super(addresses);
		init(link);
	}
	
	/** Initializes the interface.
	 * @param link the link to be attached to */
	private void init(Link link) {
		this.link=link;
		link.addLinkInterface(this);
		running=true;
	}
	
	/** Gets the link.
	 * @return the link */
	public Link getLink() {
		return link;
	}
	
	@Override
	public void send(Packet pkt, Address dest_addr) {
		//if (DEBUG) debug("send(): sending "+pkt.getPacketLength()+" bytes to "+dest_addr);
		if (DEBUG) debug("send(): to "+dest_addr+": "+ProtocolAnalyzer.exploreInner(pkt));
		link.transmit(pkt,this,dest_addr);
	}
		
	/** Processes an incoming packet.
	 * @param link the input link
	 * @param pkt the packet */
	public void processIncomingPacket(Link link, Packet pkt) {
		if (!running) return;
		// else
		//if (DEBUG) debug("processIncomingPacket(): received "+pkt.getPacketLength()+" bytes");
		if (DEBUG) debug("processIncomingPacket(): "+ProtocolAnalyzer.exploreInner(pkt));
		for (NetInterfaceListener li : getListeners())  li.onIncomingPacket(this,pkt);
	}
	
	@Override
	public void close() {
		link.removeLinkInterface(this);
		running=false;
		super.close();
	}

}
