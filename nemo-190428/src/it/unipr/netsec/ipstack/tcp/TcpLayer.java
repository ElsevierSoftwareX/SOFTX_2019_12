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

package it.unipr.netsec.ipstack.tcp;


import java.net.SocketException;
import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4LayerListener;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.SocketAddress;


/** TCP layer demultiplexes TCP connections, dispatching incoming segments to the proper TCP connections. 
 */
public class TcpLayer {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	/** IP layer */
	Ip4Layer ip_layer;
	
	/** Index of unassigned port numbers */
	int port_counter=1024;

	/** This IP layer listener */
	//Ip4ProviderListener this_ip_layer_listener;
	
	/** TCP SYN listeners */
	Hashtable<Integer,TcpLayerListener> syn_listeners=new Hashtable<Integer,TcpLayerListener>();
	
	/** TCP connection listeners */
	Hashtable<ConnectionIdentifier,TcpLayerListener> conn_listeners=new Hashtable<ConnectionIdentifier,TcpLayerListener>();

	
	/** Creates a new TCP layer.
	 * @param ip_layer IP layer */
	public TcpLayer(Ip4Layer ip_layer) throws SocketException {
		this.ip_layer=ip_layer;
		Ip4LayerListener this_ip_layer_listener=new Ip4LayerListener() {
			@Override
			public void onReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
				processReceivedPacket(ip_layer,ip_pkt);
			}
		};
		ip_layer.setListener(Ip4Packet.IPPROTO_TCP,this_ip_layer_listener);
	}
	
	/** Sets the listener for new SYN on given port number.
	 * @param port the port number
	 * @param listener the listener for the given port number */
	public void setListener(int port, TcpLayerListener listener) {
		synchronized (syn_listeners) {
			Integer iport=Integer.valueOf(port);
			if (syn_listeners.containsKey(iport)) syn_listeners.remove(iport);
			syn_listeners.put(iport,listener);
		}
	}
	
	/** Removes the listener for a given protocol number.
	 * @param port the port number */
	public void removeListener(int port) {
		synchronized (syn_listeners) {
			syn_listeners.remove(Integer.valueOf(port));
		}
	}
	
	/** Sets the listener for a given connection.
	 * @param ci the connection identifier
	 * @param listener the listener for the given port number */
	public void setListener(ConnectionIdentifier ci, TcpLayerListener listener) {
		synchronized (conn_listeners) {
			if (conn_listeners.containsKey(ci)) conn_listeners.remove(ci);
			conn_listeners.put(ci,listener);
		}
	}
		
	/** Removes the listener for a given connection.
	 * @param ci the connection identifier */
	public void removeListener(ConnectionIdentifier ci) {
		synchronized (conn_listeners) {
			conn_listeners.remove(ci);
		}
	}
	
	/** Removes a listener.
	 * @param listener the listener to be removed */
	public void removeListener(TcpLayerListener listener) {
		for (ConnectionIdentifier ci : conn_listeners.keySet()) {
			if (conn_listeners.get(ci)==listener) {
				conn_listeners.remove(ci);
				return;
			}
		}
		// else
		for (Integer iport : syn_listeners.keySet()) {
			if (syn_listeners.get(iport)==listener) {
				syn_listeners.remove(iport);
				return;
			}
		}
	}
	
	/** Gets a free port number.
	 * @return the port number */
	public int getFreePort() {
		while (syn_listeners.containsKey(new Integer(port_counter))) port_counter++;
		return port_counter++;
	}
	
	/** Gets the local address used by IP for sending packet to the specified remote address.
	 * @return the port number */
	public IpAddress getSourceAddress(IpAddress dest_ipaddr) {
		return ip_layer.getSourceAddress(dest_ipaddr);
	}
	
	/** Sends an TCP segment.
	 * @param tcp_pkt the packet to be sent */
	void send(TcpPacket tcp_pkt) {
		if (DEBUG) debug("send(): TCP packet: "+tcp_pkt);
		if (tcp_pkt.getSourceAddress()==null) {
			IpAddress src_addr=getSourceAddress((IpAddress)tcp_pkt.getDestAddress());
			if (src_addr==null) {
				if (DEBUG) debug("send(): No route to '"+tcp_pkt.getDestAddress()+"': packet discarded");
				return;
			}
			tcp_pkt.setSourceAddress(src_addr);
		}
		ip_layer.send(tcp_pkt.toIp4Packet());
	}
		
	/** Processes a received packet.
	 * @param ip_layer the IP layer
	 * @param ip_pkt the packet */
	private void processReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
		TcpPacket tcp_pkt=TcpPacket.parseTcpPacket(ip_pkt);
		if (DEBUG) debug("processReceivedPacket(): TCP packet: "+tcp_pkt);
		if (tcp_pkt.getChecksumCheck()<0) {
			if (DEBUG) debug("processReceivedPacket(): TCP packet: wrong checksum: packet discarded");
			return;
		}
		// else
		SocketAddress src_soaddr=new SocketAddress((IpAddress)tcp_pkt.getSourceAddress(),tcp_pkt.getSourcePort());
		SocketAddress dst_soaddr=new SocketAddress((IpAddress)tcp_pkt.getDestAddress(),tcp_pkt.getDestPort());
		ConnectionIdentifier ci=new ConnectionIdentifier(dst_soaddr,src_soaddr);
		if (conn_listeners.containsKey(ci)) {
			//if (DEBUG) debug("processReceivedPacket(): packet passed to connection listener");
			conn_listeners.get(ci).onReceivedPacket(this,tcp_pkt);
		}
		else {
			if (tcp_pkt.hasSyn() && tcp_pkt.getAck()<0) {
				// SYN
				Integer dst_port=Integer.valueOf(dst_soaddr.getPort());
				if (syn_listeners.containsKey(dst_port)) {
					//if (DEBUG) debug("processReceivedPacket(): packet passed to SYN listener");
					syn_listeners.get(dst_port).onReceivedPacket(this,tcp_pkt);
				}
				else {
					if (DEBUG) debug("processReceivedPacket(): no SYN listener found for port "+dst_port);
					// reset
					TcpPacket tcp_rst=new TcpPacket(dst_soaddr.getIpAddress(),dst_soaddr.getPort(),src_soaddr.getIpAddress(),src_soaddr.getPort(),0,-1,null);
					tcp_rst.setRst(true);
					send(tcp_rst);
				}							
			}
			else {
				if (DEBUG) debug("processReceivedPacket(): no listener found for this packet: discarded");				
			}
		}
	}

}
