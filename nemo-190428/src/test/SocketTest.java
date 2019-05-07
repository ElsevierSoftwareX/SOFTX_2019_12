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

package test;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.DatagramSocket;

import org.zoolu.util.Flags;


/** Utility for running a simple TCP or UDP end-point.
 */
public class SocketTest {

	private static void println(String str) {
		System.out.println(str);
	}
	
	private static void pause(long time) {
		try { Thread.sleep(time); } catch (Exception e) {}
	}
	
	private static String QUIT="quit";

	private static String MESSAGE="hello";

	private static int BUFFER_SIZE=2000;
	
	
	/** UDP server.
	 * @throws IOException  */
	private static void udpServer(final int srv_port) throws IOException {
		DatagramSocket sock=new DatagramSocket(srv_port);
		DatagramPacket pkt=new DatagramPacket(new byte[BUFFER_SIZE],BUFFER_SIZE,null,0);			
		while (true) {
			sock.receive(pkt);
			String msg=new String(pkt.getData(),pkt.getOffset(),pkt.getLength());
			println("SRV: received: "+msg);
			sock.send(pkt);
			if (msg.equals(QUIT)) break;
			//break;
		}
		pause(2000);
		sock.close();										
	}
		
	/** TCP server.
	 * @throws IOException */
	private static void tcpServer(final int srv_port) throws IOException {
		ServerSocket server=new ServerSocket(srv_port);
		Socket sock=server.accept();
		InputStream in=sock.getInputStream();
		OutputStream out=sock.getOutputStream();
		byte[] rcv_buf=new byte[BUFFER_SIZE];
		while (true) {
			int len=in.read(rcv_buf);
			String msg=new String(rcv_buf,0,len);
			println("SRV: received: "+msg);
			out.write(msg.getBytes());
			if (msg.indexOf(QUIT)>=0) break;
			//break;
		}
		pause(2000);
		sock.close();																	
	}
	
	/** UDP client.
	 * @throws IOException */
	private static void udpClient(InetAddress dst_addr, int dst_port) throws IOException {
		DatagramSocket sock=new DatagramSocket();
		byte[] data=MESSAGE.getBytes();
		DatagramPacket pkt=new DatagramPacket(data,data.length,dst_addr,dst_port);			
		println("CLI: send: "+MESSAGE);
		sock.send(pkt);
		sock.receive(pkt);
		String msg=new String(pkt.getData(),pkt.getOffset(),pkt.getLength());
		println("CLI: received: "+msg);
		sock.close();															
	}

	/** TCP client. 
	 * @throws IOException  */
	private static void tcpClient(InetAddress dst_addr, int dst_port) throws IOException {
		Socket sock=new Socket(dst_addr,dst_port);
		InputStream in=sock.getInputStream();
		OutputStream out=sock.getOutputStream();
		for (int i=0; i<10; i++) {
			String msg=String.valueOf(i);
			println("CLI: send: "+msg);
			out.write(msg.getBytes());
		}
		out.write(QUIT.getBytes());
		byte[] rcv_buf=new byte[BUFFER_SIZE];
		while (true) {
			int len=in.read(rcv_buf);
			String msg=new String(rcv_buf,0,len);
			println("CLI: received: "+msg);
			if (msg.indexOf(QUIT)>=0) break;
			//break;
		}
		pause(2000);
		sock.close();												
	}
	
	public static void main(String[] args) throws InterruptedException, IOException {
		Flags flags=new Flags(args);
		boolean use_udp=flags.getBoolean("-u","uses UDP");
		int srv_port=flags.getInteger("-s","<port>",-1,"runs an echo server on the selected port");
		String dst_soaddr=flags.getString("-d","<dest-soaddr>",null,"sends a message to the selected remote address");
		MESSAGE=flags.getString("-m","<message>","hello","sends the selected message");
		boolean verbose=flags.getBoolean("-v","verbose mode");
		boolean help=flags.getBoolean("-h","prints this help");
		
		if (help) {
			println(flags.toUsageString(SocketTest.class.getSimpleName()));
			System.exit(0);
		}
		// else
		
		// FORCE THIS CONFIGURATION
		//use_udp=true;
		//verbose=true;
		//srv_port=5000;
		//dst_soaddr="127.0.0.1:5000";		
		
		if (verbose) {
			// do something
		}
		
		// START SERVER
		if (srv_port>0) {
			final int srv_port1=srv_port;
			final boolean use_udp1=use_udp;
			new Thread(){
				public void run() {
					try {
						println("SRV: started");
						if (use_udp1) udpServer(srv_port1);
						else tcpServer(srv_port1);
						System.exit(0);
					}
					catch (Exception e) {
						e.printStackTrace();
					}					
				}
			}.start();
			pause(500);
		}
		
		// START CLIENT
		if (dst_soaddr!=null) {
			println("CLI: started");
			InetAddress dst_addr=Inet4Address.getByName(dst_soaddr.substring(0,dst_soaddr.indexOf(':')));
			int dst_port=Integer.parseInt(dst_soaddr.substring(dst_soaddr.indexOf(':')+1));
			if (use_udp) udpClient(dst_addr,dst_port);
			else tcpClient(dst_addr,dst_port);
			pause(1000);
			System.exit(0);
		}
		//pause(1000);
		//System.exit(0);
	}

}
