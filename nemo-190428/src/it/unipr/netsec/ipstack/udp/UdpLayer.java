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

package it.unipr.netsec.ipstack.udp;


import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4LayerListener;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.net.Address;

import java.net.SocketException;
import java.util.HashSet;
import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** UDP layer sends and receives UDP datagrams.
 * Incoming datagrams are dispached to the proper UDP port listener. 
 */
public class UdpLayer {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	
	/** IP layer */
	Ip4Layer ip_layer;
	
	/** This IP layer listener */
	//Ip4ProviderListener this_ip_layer_listener;
	
	/** Index of unassigned port numbers */
	int port_counter=1024;
	
	/** UDP layer listeners */
	Hashtable<Integer,UdpLayerListener> listeners=new Hashtable<Integer,UdpLayerListener>();

	

	/** Creates a new UDP layer.
	 * @param ip_layer IP layer */
	public UdpLayer(Ip4Layer ip_layer) throws SocketException {
		this.ip_layer=ip_layer;
		Ip4LayerListener this_ip_layer_listener=new Ip4LayerListener() {
			@Override
			public void onReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
				processReceivedPacket(ip_layer,ip_pkt);
			}
		};
		ip_layer.setListener(Ip4Packet.IPPROTO_UDP,this_ip_layer_listener);
	}

	
	/** Gets a free port number.
	 * @return the port number */
	public int getFreePort() {
		while (listeners.containsKey(new Integer(port_counter))) port_counter++;
		return port_counter;
	}

	
	/** Sets the listener for a given port number.
	 * @param port the port number
	 * @param listener the new listener for the given port number */
	public void setListener(int port, UdpLayerListener listener) {
		synchronized (listeners) {
			Integer key=Integer.valueOf(port);
			if (listeners.containsKey(key)) listeners.remove(key);
			listeners.put(key,listener);
		}
	}
	
	
	/** Removes the listener for a given protocol number.
	 * @param port the port number */
	public void removeListener(int port) {
		synchronized (listeners) {
			Integer key=Integer.valueOf(port);
			listeners.remove(key);
		}
	}

	
	/** Removes a listener.
	 * @param listener the listener to be removed */
	public void removeListener(UdpLayerListener listener) {
		synchronized (listeners) {
			for (Integer key : listeners.keySet()) {
				if (listeners.get(key)==listener) {
					listeners.remove(key);
					break;
				}
			}
		}
	}

	
	/** Gets a local IP address for sending datagrams to a target node.
	 * @param dst_addr address of the target node */
	public IpAddress getSourceAddress(Address dst_addr) {
		return ip_layer.getSourceAddress(dst_addr);
	}
	
	
	/** Sends an UDP packet.
	 * @param udp_pkt the packet to be sent */
	public void send(UdpPacket udp_pkt) {
		if (DEBUG) debug("send(): datagram: "+udp_pkt);
		if (udp_pkt.getSourceAddress()==null) {
			IpAddress src_addr=getSourceAddress((IpAddress)udp_pkt.getDestAddress());
			if (src_addr==null) {
				if (DEBUG) debug("send(): No route to '"+udp_pkt.getDestAddress()+"': packet discarded");
				return;
			}
			udp_pkt.setSourceAddress(src_addr);
		}
		ip_layer.send(udp_pkt.toIp4Packet());
	}
	
	
	/** Processes a received packet.
	 * @param ip_layer the IP layer
	 * @param ip_pkt the packet */
	private void processReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
		UdpPacket udp_pkt=UdpPacket.parseUdpPacket(ip_pkt);
		if (DEBUG) debug("processReceivedPacket(): datagram: "+udp_pkt);
		if (udp_pkt.getChecksumCheck()<0) {
			if (DEBUG) debug("processReceivedPacket(): UDP packet: wrong checksum: packet discarded");
			return;
		}
		Integer dst_port=Integer.valueOf(udp_pkt.getDestPort());
		if (listeners.containsKey(dst_port)) {
			listeners.get(dst_port).onReceivedPacket(this,udp_pkt);
		}
		else {
			if (DEBUG) debug("processReceivedPacket(): no listener found for port "+dst_port);
			// send destination port unreachable
			// TODO
		}
	}

}
