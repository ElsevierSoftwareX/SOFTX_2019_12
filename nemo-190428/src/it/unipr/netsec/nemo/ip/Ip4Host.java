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

package it.unipr.netsec.nemo.ip;


import java.io.IOException;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.SocketException;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.Random;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.icmp4.PingClient;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.tcp.TcpLayer;
import it.unipr.netsec.ipstack.udp.DatagramSocket;
import it.unipr.netsec.ipstack.udp.UdpLayer;
import it.unipr.netsec.nemo.http.HttpRequestHandle;
import it.unipr.netsec.nemo.http.HttpServer;
import it.unipr.netsec.nemo.http.HttpServerListener;
import it.unipr.netsec.nemo.link.DataLink;


/** IPv4 Host.
 * <p>
 * It is an IP node with a web server (port 80), a UDP echo server (port 7), and a PING client.
 */
public class Ip4Host extends Ip4Node {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Ip4Host.class.getSimpleName()+"["+getID()+"]: "+str);
	}
	
	
	/** IP layer built on top of this node and used by the PING client */
	Ip4Layer ip_layer;
	
	/** UDP layer for the echo server */
	UdpLayer udp_layer;

	/** TCP layer for the HTTP server */
	TcpLayer tcp_layer;

	
	/** Creates a new host.
	 * @param ni network interface
	 * @param gw default router */
	public Ip4Host(NetInterface ni, IpAddress gw) {
		super(new NetInterface[] {ni});
		ip_layer=new Ip4Layer(this);
		if (gw!=null) getRoutingTable().setDefaultRoute(gw);
	}

	/** Creates a new host.
	 * @param link attached link
	 * @param addr the IP address
	 * @param gw default router */
	public Ip4Host(IpLink link, Ip4Address addr, Ip4Address gw) {
		this(new IpLinkInterface(link,addr),gw);
	}
		
	/** Creates a new host.
	 * The IP address and default router are automatically configured
	 * @param link attached link */
	public Ip4Host(IpLink link) {
		this(new IpLinkInterface(link),(link.getRouters().length>0?(IpAddress)link.getRouters()[0]:null));
	}
		
	/** Gets the host address.
	 * @return the first address of the network interface */
	public Ip4Address getAddress() {
		return (Ip4Address)getNetInterfaces()[0].getAddresses()[0];
	}
	
	
	/** Starts a UDP echo server. */
	public void startUdpEchoServer() {
		try {
			udp_layer=new UdpLayer(ip_layer);
			new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						udpEchoServer(udp_layer);
					}
					catch (IOException e) {
						e.printStackTrace();
					}
				}			
			}).start();
		}
		catch (SocketException e) {
			e.printStackTrace();
		}
	}

	/** UDP echo server.
	 * @param udp_layer UDP layer 
	 * @throws IOException */
	private void udpEchoServer(UdpLayer udp_layer) throws IOException {
		DatagramSocket udp_socket=new DatagramSocket(udp_layer,7);
		DatagramPacket datagram_packet=new DatagramPacket(new byte[1024],0);
		while (true) {
			udp_socket.receive(datagram_packet);
			debug("UDP ECHO: received data: "+ByteUtils.asHex(datagram_packet.getData(),datagram_packet.getOffset(),datagram_packet.getLength()));
			datagram_packet.setPort(5555);
			debug("UDP ECHO: reply to: "+datagram_packet.getAddress().getHostAddress().toString());			
			udp_socket.send(datagram_packet);
		}		
	}
	
	/** Starts a HTTP server. */
	public void startHttpServer() {
		try {
			tcp_layer=new TcpLayer(ip_layer);
			new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						httpServer(tcp_layer);
					}
					catch (IOException e) {
						e.printStackTrace();
					}
				}
			}).start();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/** HTTP server.
	 * @param tcp_layer TCP layer
	 * @throws IOException */
	private void httpServer(TcpLayer tcp_layer) throws IOException {
		new HttpServer(tcp_layer,80,new HttpServerListener() {
			@Override
			public void onHttpRequest(HttpRequestHandle req_handle) {
				if (req_handle.getMethod().equals("GET") && req_handle.getRequestURL().equals("/")) {
					String resource_value="<html>\r\n" + 
							"<body>\r\n" + 
							"<h1>Hello, World!</h1>\r\n" +
							"<p>Random value: "+Random.nextHexString(8)+"</p>\r\n" +
							"</body>\r\n" + 
							"</html>";
					req_handle.setContentType("text/html");
					req_handle.setResourceValue(resource_value.getBytes());
					req_handle.setResponseCode(200);
				}
			}			
		});
	}
	

	/** Runs a ping session.
	 * It sends a given number of ICMP Echo Request messages and captures the corresponding ICMP Echo Reply responses.
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param out output where ping results are printed */
	public void ping(final Ip4Address target_ip_addr, int count, final PrintStream out) {
		new PingClient(ip_layer,target_ip_addr,count,out);
	}

	/*@Override
	public String toString() {
		return getClass().getSimpleName()+'['+getAddress()+']';
	}*/

}
