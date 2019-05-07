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

package it.unipr.netsec.nemo.networkfunction;



import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.ip6.exthdr.ExtensionHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.SegmentRoutingHeader;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import java.util.ArrayList;



/** Adds IPv6 SR Header with a given segment list.
 */
public class Ip6SrAddFunction extends NetworkFunction {


	/** Debug mode */
	public static boolean DEBUG=true;

	
	/** Prints a debug message. */
	private static void debug(String str) {
		if (DEBUG) SystemUtils.log(LoggerLevel.DEBUG,Ip6SrAddFunction.class,str);
	}

	
	/** Packet buffer size */
	static int BUFFER_SIZE=8192;

	/** Temporary packet buffer */
	byte[] temp_buffer=new byte[BUFFER_SIZE];

	
	/** SR header */
	ArrayList<Ip6Address> reverse_segment_list;
	
	
	/** Creates an Ip6SrAddFunction.
	 * @param reverse_segment_list segment list in reverse order */
	public Ip6SrAddFunction(ArrayList<Ip6Address> reverse_segment_list) {
		this.reverse_segment_list=reverse_segment_list;
	}

	
	@Override
	public int processPacket(byte[] buf, int len) {
		int version=(buf[0]&0xf0)>>4;
		if (version==6) {
			// IPv6 packet
			debug("input packet:\n"+ByteUtils.asHex(buf,0,len));
			int next_hdr=buf[6]&0xff;
			if (next_hdr!=ExtensionHeader.ROUTING_HDR) {
				Ip6Packet ip6_pkt=Ip6Packet.parseIp6Packet(buf,0,len);
				reverse_segment_list.add(0,(Ip6Address)ip6_pkt.getDestAddress());
				SegmentRoutingHeader srh=new SegmentRoutingHeader(reverse_segment_list.toArray(new Ip6Address[]{}));
				reverse_segment_list.remove(0);
				srh.setCleanupFlag(true);
				ip6_pkt.addExtHdr(srh);
				ip6_pkt.setDestAddress(reverse_segment_list.get(0));
				len=ip6_pkt.getBytes(temp_buffer,0);
				System.arraycopy(temp_buffer,0,buf,0,len);
				debug("output packet:\n"+ByteUtils.asHex(buf,0,len));
			}
		}
		return len;
	}

	
	/** The main method. */
	public static void main(String[] args) {
		
		try {
			int qnum=Integer.parseInt(args[0]);		
			ArrayList<Ip6Address> reverse_segment_list=new ArrayList<Ip6Address>();
			for (int i=args.length-1; i>0; i--) reverse_segment_list.add(new Ip6Address(args[i]));
			//new Ip6SrAddFunction(reverse_segment_list).runWithPromptForStopping(qnum);
			new Ip6SrAddFunction(reverse_segment_list).run(qnum);
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println("\nusage: java "+Ip6SrAddFunction.class.getName()+" qnum sid1 sid2 sid3 ..\n");
		}		
		/*try {
			int qnum=Integer.parseInt(args[0]);		
			Ip6Address local_sid=new Ip6Address(args[1]);			
			ArrayList<Ip6Address> sr_path=new ArrayList<Ip6Address>();
			for (int i=args.length-1; i>1; i--) sr_path.add(new Ip6Address(args[i]));			
			
			//new Ip6SrAddFunction((Ip6Address[])sr_path.toArray(new Ip6Address[]{})).runWithPromptForStopping(qnum);
			NetworkFunction nf1=new Ip6SrAddFunction((Ip6Address[])sr_path.toArray(new Ip6Address[]{}));
			NetworkFunction nf2=new Ip6SegmentRoutingFunction(local_sid);
			new NetworkFunctionChain(new NetworkFunction[]{nf1,nf2}).runWithPromptForStopping(qnum);
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println("\nusage: java "+Ip6SrAddFunction.class.getName()+" qnum local_sid sid1 sid2 sid3 ..\n");
		}*/			
	}	

}
