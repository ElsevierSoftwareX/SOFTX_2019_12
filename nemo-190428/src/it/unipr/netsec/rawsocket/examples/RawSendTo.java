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


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.DataPacket;
import it.unipr.netsec.rawsocket.*;

import java.io.*;

import org.zoolu.util.Flags;


/** Program for sending raw IP packets.
  * <p>
  * Usage:
  * <pre>
  *       java RawSendTo &lt;d_addr&gt; &lt;proto&gt; [options]
  *       options:
  *       -h                  this help
  *       -v                  switches in verbode mode
  *       -f &lt;file&gt;           sends data from the given file
  *       -a &lt;data&gt;           sends the given text data
  *       -x                  data is passed in hexadecimal format
  *       -r                  raw mode, that means the data includes IP header
  *       -o &lt;options&gt;        set the given IP options (in hexadecimal format)
  *       -t &lt;millisec&gt;       loops sending the same packet every given millisecs
  * </pre>
  */
public class RawSendTo {
	

	/** The main method.
	 * @param args program arguments */
	public static void main(String[] args) {
		
		Flags flags=new Flags(args);		
		boolean help=flags.getBoolean("-h","prints this message");		
		String dst_addr=flags.getString(null,"<daddr>",null,"destination address");
		//String src_addr="0.0.0.0";
		int proto=flags.getInteger(null,"<proto>",-1,"protocol number");
		boolean verbose=flags.getBoolean("-v","verbode mode");
		String file=flags.getString("-f","<file>",null,"sends data from the given file");
		String data_str=flags.getString("-a","<data>",null,"sends the given text data");
		boolean hexadecimal=flags.getBoolean("-x","data is passed in hexadecimal format");
		boolean raw_mode=flags.getBoolean("-r","raw mode, that means the data includes IP header");
		String options_str=flags.getString("-o","<options>",null,"sets the given IP options (in hexadecimal format)");
		int version=flags.getBoolean("-6","uses IPv6")? 6:4;
		int millisec=flags.getInteger("-t","<millisec>",0,"loops sending the same packet every given millisecs");
	
		if (help || proto<0)  {
			System.out.println(flags.toUsageString(RawSendTo.class.getSimpleName()));
			System.exit(0);
		}			
		
		byte[] data=null;
		//int len=0;

		if (file==null) {
			if (data_str==null) {
				System.out.println("Type the message to send:");
				try {
					BufferedReader rd=new BufferedReader(new InputStreamReader(System.in));
					data_str=rd.readLine();             
				}
				catch (Exception e) {
					System.out.println("Error reading from standard input");
					System.exit(0);
				}
			}
			if (hexadecimal) {
				data=new byte[data_str.length()/2];
				for (int k=0; k<data.length; k++) data[k]=(byte)Integer.parseInt(data_str.substring(k*2,k*2+2),16);
			}
			else {
				data=data_str.getBytes();
			}
			//len=data.length;
		}
		else {
			try {
				if (hexadecimal) {
					BufferedReader rd=new BufferedReader(new FileReader(file));
					data_str=rd.readLine();
					data=new byte[data_str.length()/2];
					for (int k=0; k<data.length; k++) data[k]=(byte)Integer.parseInt(data_str.substring(k*2,k*2+2),16);
					//len=data.length;
					rd.close();
				}
				else {
					File f=new File(file);
					BufferedInputStream is=new BufferedInputStream(new FileInputStream(f));
					data=new byte[(int)f.length()];
					is.read(data);
					//len=is.read(data);
					is.close();
				}        
			}
			catch (Exception e) {
				System.out.println("Error reading from file \""+file+"\"");
				e.printStackTrace();
				System.exit(0);
			}
		}
		
		byte[] options=null;
		if (options_str!=null) {
			options=new byte[options_str.length()/2];
			for (int k=0; k<options.length; k++) options[k]=(byte)Integer.parseInt(options_str.substring(k*2,k*2+2),16);
		}
		
		if (raw_mode) {
			// RAW MODE (IP HEADER TO BE INCLUDED)
			if (verbose) System.out.println("Raw IP mode is used");
			RawIpSocket socket=null;
			try { socket=new RawIpSocket(version,proto,true); }
			catch (Exception e) {
				System.out.println("Error creating RawIpSocket");
				System.exit(0);
			}
			while (true) {
				//data=(new Ip4Packet(new Ip4Address(src_addr),new Ip4Address(dst_addr),proto,data,0,data.length)).getBytes();
				socket.sendto(data,0,data.length,0,dst_addr,0);
				if (millisec>0) try {  Thread.sleep(millisec);  } catch (Exception e) {  e.printStackTrace();  }
				else break;
			}
		}
		else {	
			// NON-RAW MODE (IP HEADER NOT TO BE INCLUDED)
			Socket socket=null;
			try {
				socket= version==4? new Ip4Socket(proto) : version==6? new Ip6Socket(proto) : null;
				//System.out.println("DEBUG: RawSendTo: IpSocket created");
			}
			catch (Exception e) {
				System.out.println("Error creating IpSocket");
				System.exit(0);
			}
			socket.bind();
			//System.out.println("DEBUG: RawSendTo: IpSocket bound");
			DataPacket packet=null;
			if (version==6) {
				packet=new Ip6Packet(null,new Ip6Address(dst_addr),proto,data,0,data.length);
			}
			else
		    if (version==4) {
		    	packet=new Ip4Packet(null,new Ip4Address(dst_addr),proto,data,0,data.length);
		    	if (options!=null) ((Ip4Packet)packet).setOptions(options,0,options.length);
		    }
			while (true) {
				socket.send(packet);
				System.out.println("packet sent to "+dst_addr+" proto="+proto+" (len="+data.length+")");
				if (millisec>0) try {  Thread.sleep(millisec);  } catch (Exception e) {  e.printStackTrace();  }
				else break;
			}
		}
	}
}
