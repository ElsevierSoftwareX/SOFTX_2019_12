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
import it.unipr.netsec.ipstack.ip6.exthdr.RoutingHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.SegmentRoutingHeader;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;



/** IPv6 Segment-Routing (SR) function.
 * */
public class Ip6SrFunction extends NetworkFunction {

	/** Debug mode */
	public static boolean DEBUG=true;

	
	/** Prints a debug message. */
	private static void debug(String str) {
		if (DEBUG) SystemUtils.log(LoggerLevel.DEBUG,Ip6SrFunction.class,str);
	}

	
	/** Packet buffer size */
	static int BUFFER_SIZE=8192;

	/** Temporary packet buffer */
	byte[] temp_buffer=new byte[BUFFER_SIZE];
	
	
	/** Segment ID of this node */
	Ip6Address local_sid;
	
	/** Creates a new Ip6SegmentRoutingFunction.
	 * @param local_sid segment ID of this node */
	public Ip6SrFunction(Ip6Address local_sid) {
		this.local_sid=local_sid;
	}
	
	
	@Override
	public int processPacket(byte[] buf, int len) {
		int version=(buf[0]&0xf0)>>4;
		if (version==6) {
			// IPv6 packet
			Ip6Packet ip6_pkt=Ip6Packet.parseIp6Packet(buf,0,len);
			debug("input packet:\n"+ByteUtils.asHex(ip6_pkt.getBytes()));
			Ip6Address dest_addr=(Ip6Address)ip6_pkt.getDestAddress();
			if (dest_addr.equals(local_sid)) {
				if (ip6_pkt.hasExtHdr(ExtensionHeader.ROUTING_HDR)) {
					//debug(local_addrs[0]+": packet has RH");
					RoutingHeader rh=new RoutingHeader(ip6_pkt.getExtHdr(ExtensionHeader.ROUTING_HDR));
					if (rh.getRoutingType()==RoutingHeader.TYPE_SRH) {
						debug("packet has SRH");
						SegmentRoutingHeader srh=new SegmentRoutingHeader(rh);
						int segment_left=srh.getSegmentLeft();
						if (segment_left>0) {
							debug("there are more segments");
							srh.setSegmentLeft(--segment_left);
							dest_addr=srh.getSegmentAt(segment_left);
							ip6_pkt.setDestAddress(dest_addr);
							if (segment_left==0) {
								// IF Clean-up bit is set THEN remove the SRH
								debug("last segment");
								if (srh.getCleanupFlag()) {
									debug("clean-up");
									ip6_pkt.removeExtHdr(ExtensionHeader.ROUTING_HDR);
								}
							}
							// return the new packet
							len=ip6_pkt.getBytes(temp_buffer,0);
							System.arraycopy(temp_buffer,0,buf,0,len);				
							debug("output packet:\n"+ByteUtils.asHex(buf,0,len));
							//return len;
							
							// process the new packet in case of spiral routing
							//len=processPacket(buf,len);
						}
						else {
							// give the packet to the next PID (application)
							debug("end of segments");
						}
					}
				}
			}
		}
		return len;
	}

	
	/** The main method. */
	public static void main(String[] args) {
			
		try {
			int qnum=Integer.parseInt(args[0]);		
			Ip6Address local_sid=new Ip6Address(args[1]);			
			//new Ip6SrFunction(local_sid).runWithPromptForStopping(qnum);
			new Ip6SrFunction(local_sid).run(qnum);
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println("\nusage: java "+Ip6SrFunction.class.getName()+" qnum local_sid\n");
		}		
}	

}
