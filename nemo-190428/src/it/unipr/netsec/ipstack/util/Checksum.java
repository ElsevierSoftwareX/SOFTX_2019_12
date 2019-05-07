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

package it.unipr.netsec.ipstack.util;



/** IP, ICMP, UDP, TCP checksum.
 */
public class Checksum {
	
	/** Checksum calculation.
	 * It computes the Internet checksum of a given array of bytes (data).
	 * @param buf the buffer containing the data for computing the checksum
	 * @param off the offset of the data within the buffer
	 * @param len the data length */
	public static int checksum(byte[] buf, int off, int len) {
		int sum=0;
		//for (int i=0; i<len; i+=2) sum+=((buf[off+i]&0xff)<<8) + ((i+1)<len? buf[off+i+1]&0xff : 0x00);
		for (int i=0; i<len; i++) sum+=(i&0x1)==0x0? (buf[off+i]&0xff)<<8 : buf[off+i]&0xff;
		while ((sum>>16)!=0) sum=(sum&0xffff)+(sum>>16);
		return ~sum;
	}

	
	/** Upper-layer checksum calculation including IPv4 pseudo-header as defined in RFC 768.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param protocol upper-layer protocol
	 * @param buf the buffer containing the data for computing the checksum
	 * @param off the offset of the data within the buffer
	 * @param len the data length
	 * @return the checksum */ 
	public static int transportChecksum4(byte[] src_addr, byte[] dst_addr, int protocol, byte[] buf, int off, int len) {
		int sum=0;
		for (int i=0; i<4; i+=2) sum+=((src_addr[i]&0xff)<<8) + (src_addr[i+1]&0xff);
		for (int i=0; i<4; i+=2) sum+=((dst_addr[i]&0xff)<<8) + (dst_addr[i+1]&0xff);
		sum+=protocol&0xff;
		sum+=len&0xffff;
		for (int i=0; i<len; i++) sum+=(i&0x1)==0x0? (buf[off+i]&0xff)<<8 : buf[off+i]&0xff;
		while ((sum>>16)!=0) sum=(sum&0xffff)+(sum>>16);
		return ~sum;
	}

	
	/** Upper-layer checksum calculation including IPv6 pseudo-header as defined in RFC 2460.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param next_hdr next header
	 * @param buf the buffer containing the data for computing the checksum
	 * @param off the offset of the data within the buffer
	 * @param len the data length
	 * @return the checksum */ 
	public static int transportChecksum6(byte[] src_addr, byte[] dst_addr, int next_hdr, byte[] buf, int off, int len) {
		int sum=0;
		for (int i=0; i<16; i+=2) sum+=((src_addr[i]&0xff)<<8) + (src_addr[i+1]&0xff);
		for (int i=0; i<16; i+=2) sum+=((dst_addr[i]&0xff)<<8) + (dst_addr[i+1]&0xff);
		sum+=(len>>16)&0xffff;
		sum+=len%0xffff;
		sum+=0;
		sum+=next_hdr&0xff;
		for (int i=0; i<len; i++) sum+=(i&0x1)==0x0? (buf[off+i]&0xff)<<8 : buf[off+i]&0xff;
		while ((sum>>16)!=0) sum=(sum&0xffff)+(sum>>16);
		return ~sum;
	}
	
}
