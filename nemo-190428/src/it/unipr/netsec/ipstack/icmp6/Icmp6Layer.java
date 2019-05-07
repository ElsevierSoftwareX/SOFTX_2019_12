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

package it.unipr.netsec.ipstack.icmp6;


import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoReplyMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoRequestMessage;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Layer;
import it.unipr.netsec.ipstack.ip6.Ip6LayerListener;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;

import java.util.ArrayList;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** ICMPv6 service.
 * It allows the user to send and receive ICMPv6 messages.
 * It automatically responds to ICMPv6 Echo requests.
 */
public class Icmp6Layer {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** IP layer */
	Ip6Layer ip_layer;

	/** This IP layer listener */
	Ip6LayerListener this_ip_listener;
	
	/** ICMPv6 layer listeners */
	ArrayList<Icmp6LayerListener> listeners=new ArrayList<Icmp6LayerListener>();
	
	
	
	/** Creates a new ICMPv6 interface.
	 * @param ip_layer the IP layer */
	public Icmp6Layer(Ip6Layer ip_layer) {
		this.ip_layer=ip_layer;
		Ip6LayerListener this_ip_listener=new Ip6LayerListener() {
			@Override
			public void onReceivedPacket(Ip6Layer ip_layer, Ip6Packet ip_pkt) {
				processReceivedPacket(ip_layer,ip_pkt);
			}
		};
		ip_layer.setListener(Ip6Packet.IPPROTO_ICMP6,this_ip_listener);
	}

	
	/** Adds a listener for receiving incoming ICMPv6 messages.
	 * @param listener the listener to be added */
	public void addListener(Icmp6LayerListener listener) {
		synchronized (listeners) {
			listeners.add(listener);
		}
	}
	
	
	/** Removes an ICMPv6 listener.
	 * @param listener the listener to be removed */
	public void removeListener(Icmp6LayerListener listener) {
		synchronized (listeners) { 
			for (int i=0; i<listeners.size(); i++) {
				Icmp6LayerListener listener_i=listeners.get(i);
				if (listener_i==listener) {
					listeners.remove(listener_i);
				}
			}
		}
	}

	
	/** Gets a local IP address for sending ICMPv6 messages to a target node.
	 * @param dst_addr address of the target node
	 * @return the IP address */
	public Ip6Address getSourceAddress(Address dst_addr) {
		return ip_layer.getSourceAddress(dst_addr);
	}
	
	
	/** Sends an ICMPv6 message.
	 * @param icmp_msg the packet to be sent */
	public void send(Icmp6Message icmp_msg) {
		if (DEBUG) debug("send(): ICMP message: "+icmp_msg);
		ip_layer.send(icmp_msg.toIp6Packet());
	}

	
	/** Processes an incoming IP packet. */
	private void processReceivedPacket(Ip6Layer ip_layer, Ip6Packet ip_pkt) {
		Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
		if (DEBUG) debug("processReceivedPacket(): ICMP message: "+icmp_msg);
		if (icmp_msg.getType()==Icmp6Message.TYPE_Echo_Request) {
			Icmp6EchoRequestMessage icmp_echo_request=new Icmp6EchoRequestMessage(icmp_msg);
			if (DEBUG) debug("processReceivedPacket(): ICMPv6 Echo request from "+icmp_echo_request.getSourceAddress());
			Icmp6EchoReplyMessage icmp_echo_reply=new Icmp6EchoReplyMessage((Ip6Address)icmp_echo_request.getDestAddress(),(Ip6Address)icmp_echo_request.getSourceAddress(),icmp_echo_request.getIdentifier(),icmp_echo_request.getSequenceNumber(),icmp_echo_request.getEchoData());
			send(icmp_echo_reply);
		}
		else {
			for (Icmp6LayerListener listener_i : listeners) listener_i.onReceivedIcmpMessage(this,ip_pkt);
		}
	}

	
	/** Closes this ICMP service.
	 * No more messages can be sent or received. */
	public void close() {
		ip_layer.removeListener(this_ip_listener);
		ip_layer=null;
	}	

}
