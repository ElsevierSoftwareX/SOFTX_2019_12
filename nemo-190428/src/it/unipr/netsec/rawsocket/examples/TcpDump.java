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

package it.unipr.netsec.rawsocket.examples;


import it.unipr.netsec.ipstack.analyzer.LibpcapHeader;
import it.unipr.netsec.ipstack.analyzer.LibpcapTrace;
import it.unipr.netsec.ipstack.analyzer.ProtocolAnalyzer;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.rawsocket.RawLinkSocket;

import java.io.IOException;

import org.zoolu.util.Flags;


/** It analyzes all packets captured at data-link level.
 * <p> 
 * It uses {@link it.unipr.netsec.rawsocket.RawLinkSocket}, that in turn uses a PF_PACKET SOCK_RAW socket.
 * Since PF_PACKET SOCK_RAW sockets are not supported neither in Windows OS neither nor in Mac OS,
 * TcpDump can be run only on Linux OS.
 */
public class TcpDump {
	
	/** Maximum receiver buffer size */
	public static int RECV_BUFF_SIZE=65535;
	
	
	/** The main method. 
	 * @throws IOException */
	public static void main(String[] args) throws IOException {
		
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		//boolean verbose=flags.getBoolean("-v","runs in verbose mode");
		int count=flags.getInteger("-c","<num>",-1,"captures the given number of packets and exits");
		boolean no_ssh=flags.getBoolean("-nossh","suppresses output for ssh packets (TCP port 22)");
		String out_file=flags.getString("-out","<file>",null,"writes the trace to the given file");
				
		if (help || flags.size()>0) {
			System.out.println(flags.toUsageString(TcpDump.class.getSimpleName()));
			return;			
		}
		/*if (verbose) {
			System.out.println("Network interfaces:");
			for (Enumeration<NetworkInterface> i=NetworkInterface.getNetworkInterfaces(); i.hasMoreElements(); ) {
				NetworkInterface ni=i.nextElement();
				System.out.println(" - "+ni.getName()+" ("+ni.getDisplayName()+")");
			}			
		}*/
		LibpcapTrace trace=out_file!=null? new LibpcapTrace(LibpcapHeader.LINKTYPE_ETHERNET,out_file) : null; 
		RawLinkSocket raw_socket=new RawLinkSocket();
		byte[] buf=new byte[RECV_BUFF_SIZE];
		while (count!=0) {
			int len=raw_socket.recv(buf,0,0);
			EthPacket pkt=EthPacket.parseEthPacket(buf,0,len);
			String dump=ProtocolAnalyzer.packetDump(pkt);
			if (!no_ssh || dump.indexOf(":22 ")<0) {
				System.out.println(dump);
				if (trace!=null) trace.add(pkt);
				if (count>0) count--;
			}
		}	
	}
}
