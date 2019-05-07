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

package it.unipr.netsec.netfilter.examples;



import it.unipr.netsec.netfilter.*;



/** It mangles ICMP packets.
 * <p>
 * Packets with IP protocol field = 1 (ICMP) are modified by changing the protocol field to 50 (ESP) 
 * and by adding the original IP protocol type (1) at the end of the packet; the packet length is increased by 1.
 * Packets with IP protocol field = 50 (ESP) are restored with the original protocol field and packet length.
 */
public class IcmpPacketHandler implements PacketHandler {

	/** ICMP protocol type */
	static final int PROTO_ICMP=1; 

	/** ESP protocol type */
	static final int PROTO_ESP=50; 

	/** ICMP ECHO REQUEST type */
	static final int ICMP_ECHO_REQUEST=8; 

	/** ICMP ECHO REPLY type */
	static final int ICMP_ECHO_REPLY=0; 

	/** TOS field offset */
	static final int OFFSET_TOS=1; 

	/** TTL field offset */
	static final int OFFSET_TTL=8; 

	/** Protocol field offset */
	static final int OFFSET_PROTO=9; 
	
	/** ICMP Type field offset */
	static final int OFFSET_ICMP_TYPE=20; 

	

	/** Verbose mode */
	boolean verbose=false;

	
	
	/** Creates a queue handler. */
	public IcmpPacketHandler() {
	}
	

	/** Creates a queue handler.
	 * @param verbose verbose mode*/
	public IcmpPacketHandler(boolean verbose) {
		this.verbose=verbose;
	}
	

	@Override
	public int processPacket(byte[] buf, int len) {
		if (verbose) System.out.println("DEBUG: IN: "+len+" bytes\n"+asHex(buf,0,len));

		if (buf[OFFSET_PROTO]==PROTO_ICMP && (buf[OFFSET_ICMP_TYPE]==ICMP_ECHO_REQUEST || buf[OFFSET_ICMP_TYPE]==ICMP_ECHO_REPLY)) {
			// encode the packet
			buf[len]=buf[OFFSET_PROTO];
			buf[OFFSET_PROTO]=PROTO_ESP;
			len++;
		}
		else
		if (buf[OFFSET_PROTO]==PROTO_ESP) {
			// decode the packet
			buf[OFFSET_PROTO]=buf[len-1];
			len--;
		}
		if (verbose) System.out.println("DEBUG: OUT: "+len+" bytes\n"+asHex(buf,0,len)+"\n\n");

		return len;
	}

	
	/** Gets a hexadecimal representation of an array of bytes.
     * @param buf the byte array
     * @param off the offset of the first byte 
     * @param len the number of bytes
     * @return the hexadecimal string */
	private static String asHex(byte[] buf, int off, int len) {
		final char[] hex=new char[]{'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
		char[] str=new char[len*2+(len-1)/2+(len-1)/16];
		int index=0;
		for (int count=0; count<len; count++) {
			if (count>0) {
				if (count%16==0) str[index++]='\n';
				else
				if (count%2==0) str[index++]=' ';
			}
			byte b=buf[off++];
			str[index++]=hex[(b&0xF0)>>4];
			str[index++]=hex[b&0x0F];
		}
		return new String(str);
	}

}
