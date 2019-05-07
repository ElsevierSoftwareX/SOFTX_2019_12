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


import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.DataPacket;
import it.unipr.netsec.rawsocket.*;

import java.io.*;
import java.util.Calendar;

import org.zoolu.util.Flags;


/** Program for receiving raw IP packets.
  * <p>
  * Usage:
  * <pre> &nbsp;&nbsp; java RawReceive &lt;d_addr&gt; &lt;proto&gt; [ &lt;file&gt; [&lt;millisec&gt;] ] </pre>
  */
public class RawReceive {
	
	/** Maximum receiver buffer size */
	public static int RECV_BUFF_SIZE=65535;


	/** The main method.
	 * @param args program arguments */
	public static void main(String[] args) {
		
		Flags flags=new Flags(args);		
		boolean help=flags.getBoolean("-h","prints this message");		
		int proto=flags.getInteger(null,"<proto>",-1,"protocol number");
		boolean verbose=flags.getBoolean("-v","verbode mode");
		String file=flags.getString("-f","<file>",null,"write data to the given file");
		boolean hexadecimal=flags.getBoolean("-x","data is written in hexadecimal format");
		boolean raw_mode=flags.getBoolean("-r","raw mode; also IP header is showed");
		boolean l2_raw_mode=flags.getBoolean("-r2","layer-2 raw mode");
		int version=flags.getBoolean("-6","uses IPv6")? 6:4;
		int count=flags.getInteger("-c","<count>",1,"stop after received a given number of packets ('-1' for continue mode)");
			
		if (help || proto<0)  {
			System.out.println(flags.toUsageString(RawSendTo.class.getSimpleName()));
			System.exit(0);
		}			
				
		try {
			Socket socket=null;
			if (l2_raw_mode) socket=new RawLinkSocket();
			else if (raw_mode) socket=new RawIpSocket(version,proto,true);
				else if (version==6) socket=new Ip6Socket(proto);
					else socket=new Ip4Socket(proto);
			  
			byte[] buf=new byte[RECV_BUFF_SIZE];
				
			PrintStream os;
			if (file!=null) {
				File f=new File(file);
				os=new PrintStream(new FileOutputStream(f));
			}
			else os=System.out;
		
			while (count!=0) {
				byte[] data=buf;
				int off=0;
				int len;
				String s_addr=null;
				String d_addr="this_host";
				DataPacket pkt;
				if (l2_raw_mode) {
					do { len=socket.recv(data,0,0); }
					while (!((version==4 && ((data[12]&0xff)==0x08 && (data[13]&0xff)==0x00) && (data[14]&0xf0)==0x40 && (data[14+9]&0xff)==proto) ||
						     (version==6 && ((data[12]&0xff)==0x86 && (data[13]&0xff)==0xdd) && (data[14]&0xf0)==0x60 && (data[14+6]&0xff)==proto)));
					pkt=version==6? Ip6Packet.parseIp6Packet(data,14,len) : Ip4Packet.parseIp4Packet(data,14,len);
				}
				else
				if (raw_mode) {
					len=socket.recv(data,0,0);
					if (version==6) throw new RuntimeException("IPv6 in 'raw' mode is not supported");
					pkt=Ip4Packet.parseIp4Packet(data,0,len);
				}
				else {
					pkt=version==6? ((Ip6Socket)socket).receive() : ((Ip4Socket)socket).receive();
				}
				data=pkt.getPayloadBuffer();
				off=pkt.getPayloadOffset();
				len=pkt.getPayloadLength();
				s_addr=pkt.getSourceAddress().toString();
				d_addr=pkt.getDestAddress().toString();
				
				System.out.println();
				Calendar now = Calendar.getInstance();
				os.print(now.get(Calendar.HOUR_OF_DAY)+":"+now.get(Calendar.MINUTE)+":"+now.get(Calendar.SECOND)+"."+now.get(Calendar.MILLISECOND)+" ");
				os.print(s_addr);
				os.print(" --> "+d_addr);
				os.println(" proto="+proto+" (len="+len+")");
				
				if (hexadecimal) {
					StringBuffer sb=new StringBuffer();
					for (int i=0; i<len; i++) sb.append(Integer.toHexString((data[off+i]>>4)&0x0F)).append(Integer.toHexString(data[off+i]&0x0F));
					data=sb.toString().getBytes();
					off=0;
					len=data.length;
				}
				os.write(data,off,len);
				os.println("");
				os.flush();
				
				if (len==((raw_mode)?((hexadecimal)?40:20):0)) System.exit(0);
				
				if (count>0) count--;
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
