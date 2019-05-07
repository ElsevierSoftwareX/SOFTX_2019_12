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

package it.unipr.netsec.tuntap.examples;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.netstack.LossyIpInterface;
import it.unipr.netsec.ipstack.tcp.TcpConnection;
import it.unipr.netsec.ipstack.tcp.TcpConnectionListener;
import it.unipr.netsec.ipstack.tcp.TcpLayer;
import it.unipr.netsec.tuntap.Ip4TunInterface;
import it.unipr.netsec.tuntap.Ip4TuntapInterface;

import java.io.IOException;

import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** TCP client running onto a IPv4 node attached to a TUN interface.
 * */
public class TcpClient {

	/** Prints a message. */
	private static void println(String str) {
		System.out.println("OUT: "+TcpClient.class.getSimpleName()+": "+str);
	}
	
	static Object connected=new Object();

	/** The main method. */
	public static void main(String[] args) throws IOException {
		Flags flags=new Flags(args);
		boolean verbose=flags.getBoolean("-v","verbose mode");
		boolean help=flags.getBoolean("-h","prints this message");
		long delay=flags.getLong("-t","<mean-delay>",0,"packet delay [time_nanosecs]");
		double loss=flags.getDouble("-e","<error-rate>",0,"packet error rate");
		String tuntap_interface=flags.getString(null,"<tuntap>",null,"TUN/TAP interface (e.g. 'tun0')");
		String ipaddr_prefix=flags.getString(null,"<ipaddr/prefix>",null,"IPv4 address and prefix length (e.g. '10.1.1.3/24')");
		SocketAddress remote_soaddr=new SocketAddress(flags.getString(null,"<ipaddr:port>",null,"TCP server socket address (ipaddr:port)"));
		String default_router=flags.getString(null,"<router>",null,"IPv4 address of the default router");
		
		if (help || remote_soaddr==null) {
			System.out.println(flags.toUsageString(TcpClient.class.getSimpleName()));
			System.exit(0);					
		}	
		if (verbose) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			Ip4TunInterface.DEBUG=true;
			LossyIpInterface.DEBUG=true;
			//Node.DEBUG=true;
			//Ip4Layer.DEBUG=true;
			//NewTcpLayer.DEBUG=true;
			TcpConnection.DEBUG=true;
		}
		NetInterface ni=new Ip4TuntapInterface(tuntap_interface,new Ip4AddressPrefix(ipaddr_prefix));
		Ip4Layer ip4_layer=new Ip4Layer(new NetInterface[]{new LossyIpInterface(ni,delay,loss,delay,loss)});
		if (default_router!=null) ip4_layer.getRoutingTable().setDefaultRoute(new Ip4Address(default_router));
		TcpLayer tcp=new TcpLayer(ip4_layer);

		final TcpConnectionListener this_conn_listener=new TcpConnectionListener() {
			@Override
			public void onConnected(final TcpConnection tcp_conn) {
				println("Connected");
				//tcp_conn.setListener(this_conn_listener);
				new Thread(){
					@Override
					public void run() {
						//tcp_conn.send("hello".getBytes());
						int n=100;
						int len=Integer.toString(n-1).length();
						for (int i=0; i<n; i++) {
							String str=Integer.toString(i); while (str.length()<len) str="0"+str;
							tcp_conn.send(str.getBytes());
							try { Thread.sleep(100); } catch (InterruptedException e) {}
						}
						try { Thread.sleep(2000); } catch (InterruptedException e) {}
						tcp_conn.close();
						try { Thread.sleep(8000); } catch (InterruptedException e) {}
						System.exit(0);						
					}
				}.start();
			}
			@Override
			public void onReceivedData(TcpConnection tcp_conn, byte[] buf, int off, int len) {
				String str=new String(buf,off,len);
				println("received: "+str);
			}
			@Override
			public void onClose(TcpConnection tcp_conn) {
				println("Connection remotely closing");
				tcp_conn.close();
			}
			@Override
			public void onReset(TcpConnection tcp_conn) {
				println("Connection reset");
			}
			@Override
			public void onClosed(TcpConnection tcp_conn) {
				println("Connection closed");
				System.exit(0);
			}
		};
		
		println("Contacting remote server "+remote_soaddr);		
		new TcpConnection(tcp,null,0,this_conn_listener).connect(remote_soaddr);
	}
}
