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

package it.unipr.netsec.ipstack.icmp4;


import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoReplyMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoRequestMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4LayerListener;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.routing.Route;

import java.util.ArrayList;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** ICMP service.
 * It allows the user to send and receive ICMP messages.
 * It automatically responds to ICMP Echo requests.
 */
public class IcmpLayer {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** IP layer */
	Ip4Layer ip_layer;

	/** This IP layer listener */
	Ip4LayerListener this_ip_listener;
	
	/** ICMP layer listeners */
	ArrayList<IcmpLayerListener> listeners=new ArrayList<IcmpLayerListener>();
	
	
	
	/** Creates a new ICMP interface.
	 * @param ip_layer the IP layer */
	public IcmpLayer(Ip4Layer ip_layer) {
		if (DEBUG) debug("new IcmpLayer");
		this.ip_layer=ip_layer;
		Ip4LayerListener this_ip_listener=new Ip4LayerListener() {
			@Override
			public void onReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
				processReceivedPacket(ip_layer,ip_pkt);
			}
		};
		ip_layer.setListener(Ip4Packet.IPPROTO_ICMP,this_ip_listener);
	}

	
	/** Adds a listener for receiving incoming ICMP messages.
	 * @param listener the listener to be added */
	public void addListener(IcmpLayerListener listener) {
		synchronized (listeners) {
			listeners.add(listener);
		}
	}
	
	
	/** Removes an ICMP listener.
	 * @param listener the listener to be removed */
	public void removeListener(IcmpLayerListener listener) {
		synchronized (listeners) { 
			for (int i=0; i<listeners.size(); i++) {
				IcmpLayerListener listener_i=listeners.get(i);
				if (listener_i==listener) {
					listeners.remove(listener_i);
				}
			}
		}
	}

	
	/** Gets a local IP address for sending ICMP messages to a target node.
	 * @param dst_addr address of the target node
	 * @return the IP address */
	public Ip4Address getSourceAddress(Address dst_addr) {
		return ip_layer.getSourceAddress(dst_addr);
	}
	
	
	/** Sends an ICMP message.
	 * @param icmp_msg the packet to be sent */
	public void send(IcmpMessage icmp_msg) {
		if (DEBUG) debug("send(): ICMP message: "+icmp_msg);
		ip_layer.send(icmp_msg.toIp4Packet());
	}

	
	/** Processes an incoming IP packet. */
	private void processReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
		IcmpMessage icmp_msg=new IcmpMessage(ip_pkt.getSourceAddress(),ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
		if (DEBUG) debug("processReceivedPacket(): ICMP message: "+icmp_msg);
		if (icmp_msg.getType()==IcmpMessage.TYPE_Echo_Request) {
			IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(icmp_msg);
			if (DEBUG) debug("processReceivedPacket(): ICMP Echo request from "+icmp_echo_request.getSourceAddress());
			IcmpEchoReplyMessage icmp_echo_reply=new IcmpEchoReplyMessage(icmp_echo_request.getDestAddress(),icmp_echo_request.getSourceAddress(),icmp_echo_request.getIdentifier(),icmp_echo_request.getSequenceNumber(),icmp_echo_request.getEchoData());
			send(icmp_echo_reply);
		}
		else {
			for (IcmpLayerListener listener_i : listeners) listener_i.onReceivedIcmpMessage(this,ip_pkt);
		}
	}

	
	/** Closes this ICMP service.
	 * No more messages can be sent or received. */
	public void close() {
		ip_layer.removeListener(this_ip_listener);
		ip_layer=null;
	}	

}
