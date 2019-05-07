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
import it.unipr.netsec.ipstack.ip6.exthdr.DestinationOptionsHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.ExtensionHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.ExtensionHeaderOption;
import it.unipr.netsec.ipstack.ip6.exthdr.RoutingHeader;
import it.unipr.netsec.ipstack.ip6.exthdr.SegmentRoutingHeader;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;



/** It mangles the IPv6 header in order to masquerade the presence of the IPv6 SR Header (SRH).
 * <p>
 * If SRH is present, it is moved within the Destination Options header.
 * If a copy of SRH is in the Destination Options header, it is moved back as extension header.
 */
public class Ip6SrMangleFunction extends NetworkFunction {


	/** Debug mode */
	public static boolean DEBUG=true;

	
	/** Prints a debug message. */
	private static void debug(String str) {
		if (DEBUG) SystemUtils.log(LoggerLevel.DEBUG,Ip6SrMangleFunction.class,str);
	}

	
	/** SRH option type */
	public static int OPT_TYPE_SRH=7;


	/** Packet buffer size */
	static int BUFFER_SIZE=8192;

	/** Temporary packet buffer */
	byte[] temp_buffer=new byte[BUFFER_SIZE];

	/** SRH processing function */
	Ip6SrFunction srf=null;
	

	
	/** Creates an Ip6SrMangleFunction. */
	public Ip6SrMangleFunction() {
	}

	/** Creates an Ip6SrMangleFunction.
	 * @param local_sid segment ID of this node */
	public Ip6SrMangleFunction(Ip6Address local_sid) {
		if (local_sid!=null) srf=new Ip6SrFunction(local_sid);
	}

	
	@Override
	public int processPacket(byte[] buf, int len) {
		int version=(buf[0]&0xf0)>>4;
		if (version==6) {
			// IPv6 packet
			debug("input packet:\n"+ByteUtils.asHex(buf,0,len));
			Ip6Packet ip6_pkt=Ip6Packet.parseIp6Packet(buf,0,len);
			if (srf!=null && ip6_pkt.hasExtHdr(ExtensionHeader.ROUTING_HDR)) {
				// process SRH
				len=srf.processPacket(buf,len);
				ip6_pkt=Ip6Packet.parseIp6Packet(buf,0,len);
				// mangle the SRH
				RoutingHeader rh=(RoutingHeader)ip6_pkt.getExtHdr(ExtensionHeader.ROUTING_HDR);
				if (rh.getRoutingType()==RoutingHeader.TYPE_SRH) {
					SegmentRoutingHeader srh=new SegmentRoutingHeader(rh);
					DestinationOptionsHeader doh=new DestinationOptionsHeader(new ExtensionHeaderOption[]{new ExtensionHeaderOption(OPT_TYPE_SRH,srh.getBytes())});
					ip6_pkt.removeExtHdr(ExtensionHeader.ROUTING_HDR);
					ip6_pkt.addExtHdr(doh);
					ip6_pkt.setDestAddress(srh.getSegmentAt(0));
					len=ip6_pkt.getBytes(temp_buffer,0);
					System.arraycopy(temp_buffer,0,buf,0,len);
					debug("output packet:\n"+ByteUtils.asHex(buf,0,len));					
				}
			}
			else
			if (srf==null && ip6_pkt.hasExtHdr(ExtensionHeader.DST_OPTIONS_HDR)) {
				// unmangle the SRH
				DestinationOptionsHeader doh=(DestinationOptionsHeader)ip6_pkt.getExtHdr(ExtensionHeader.DST_OPTIONS_HDR);
				debug("Destination Options header: "+ByteUtils.asHex(doh.getBytes()));
				//debug("Option: "+ByteUtils.asHex(doh.getOptions()[0].getBytes()));
				debug("Option value: "+ByteUtils.asHex(doh.getOptions()[0].getValue()));
				SegmentRoutingHeader srh=new SegmentRoutingHeader(new RoutingHeader(doh.getOptions()[0].getValue()));
				ip6_pkt.removeExtHdr(ExtensionHeader.DST_OPTIONS_HDR);
				ip6_pkt.addExtHdr(srh);
				ip6_pkt.setDestAddress(srh.getSegmentAt(srh.getSegmentLeft()));
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
			Ip6Address local_sid=args.length>1? new Ip6Address(args[1]) : null;						
			//new Ip6SrMangleFunction(local_sid).runWithPromptForStopping(qnum);
			new Ip6SrMangleFunction(local_sid).run(qnum);
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println("\nusage: java "+Ip6SrMangleFunction.class.getName()+" qnum [local_sid]\n");
		}		
	}	

}
