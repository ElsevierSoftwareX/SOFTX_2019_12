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

package it.unipr.netsec.ipstack.icmp6;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.util.Checksum;


/** ICMPv6 (Internet Control Message Protocol for IPv6) message.
 */
public class Icmp6Message implements Packet {

    // ICMPv6 error messages from RFC 4443:

    /** ICMP6 Type - Destination Unreachable */
	public static final int TYPE_Destination_Unreachable=1;

	/** ICMP6 Type - Packet Too Big */
	public static final int TYPE_Packet_Too_Big=2;

	/** ICMP6 Type - Time Exceeded */
	public static final int TYPE_Time_Exceeded=3;

	/** ICMP6 Type - Parameter Problem */
	public static final int TYPE_Parameter_Problem=4;

	
	// ICMPv6 informational messages from RFC 4443:

    /** ICMP Type: Echo Request */
	public static final int TYPE_Echo_Request=128;

	/** ICMP Type: Echo Reply */
	public static final int TYPE_Echo_Reply=129;

	
	// ICMPv6 informational messages from RFC 4861:
	
	/** ICMP Type: Router Solicitation */
	public static final int TYPE_Router_Solicitation=133;
	
	/** ICMP Type: Router Advertisement */
	public static final int TYPE_Router_Advertisement=134;
	
	/** ICMP Type: Neighbor Solicitation */
	public static final int TYPE_Neighbor_Solicitation=135;
	
	/** ICMP Type: Neighbor Advertisement */
	public static final int TYPE_Neighbor_Advertisement=136;
	
	/** ICMP Type: Redirect */
	public static final int TYPE_Redirect=137;
	
	/** ICMP Type:  */
	//public static final int TYPE_=;

	
	/** IP source address */
	protected Ip6Address src_addr;
	
	/** IP destination address */
	protected Ip6Address dst_addr;
	
	/** ICMP type */
	protected int type;
	
	/** ICMP subtype code */
	protected int code;
	
	/** Error checking data, calculated from the ICMP header and data, with value 0 substituted for this field */
	//protected int checksum;
	
	/** The ICMP message body, that is the ICMP message excluding the first 4 bytes */
	protected byte[] icmp_body;
	
	
	/** Creates a new ICMP packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code */
	protected Icmp6Message(Ip6Address src_addr, Ip6Address dst_addr, int type, int code) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.type=type;
		this.code=code;
		icmp_body=null;
	}

	/** Creates a new ICMP packet.
	 * @param msg the ICMP packet */
	protected Icmp6Message(Icmp6Message msg) {
		src_addr=msg.src_addr;
		dst_addr=msg.dst_addr;
		type=msg.type;
		code=msg.code;
		icmp_body=new byte[msg.icmp_body.length];
		System.arraycopy(msg.icmp_body,0,icmp_body,0,icmp_body.length);
	}

	/** Creates a new ICMP packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code
	 * @param buf buffer containing the ICMP packet excluding the first 4 bytes
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP packet minus 4 */
	public Icmp6Message(Ip6Address src_addr, Ip6Address dst_addr, int type, int code, byte[] buf, int off, int len) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.type=type;
		this.code=code;
		this.icmp_body=new byte[len];
		System.arraycopy(buf,off,icmp_body,0,len);		
	}

	/** Creates a new ICMP packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf buffer containing the ICMP packet
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP packet */
	public Icmp6Message(Ip6Address src_addr, Ip6Address dst_addr, byte[] buf, int off, int len) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		type=buf[off]&0xff;
		code=buf[off+1]&0xff;
		int checksum=Checksum.transportChecksum6(src_addr.getBytes(),dst_addr.getBytes(),Ip6Packet.IPPROTO_ICMP6,buf,off,len) & 0xffff;
		if (checksum!=0x0000 && checksum!=0xffff) throw new RuntimeException("Wrong ICMPv6 checksum");
		// else
		icmp_body=new byte[len-4];
		System.arraycopy(buf,off+4,icmp_body,0,icmp_body.length);
	}

	/** Creates a new ICMP packet.
	 * @param ip_pkt IPv6 packet containing the ICMP packet */
	public Icmp6Message(Ip6Packet ip_pkt) {
		this((Ip6Address)ip_pkt.getSourceAddress(),(Ip6Address)ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
	}

	/** Gets the IP source address.
	 * @return the source IP address */
	@Override
	public Address getSourceAddress() {
		return src_addr;
	}

	/** Gets the IP destination address.
	 * @return the destination IP address */
	@Override
	public Address getDestAddress() {
		return dst_addr;
	}

	/** Gets the message type.
	 * @return the type */
	public int getType() {
		return type;
	}
	
	/** Gets the subtype code.
	 * @return the subtype code */
	public int getCode() {
		return code;
	}

	/** Whether is error or informational message.
	 * @return <i>true</i> if error message, <i>false</i> if informational message */
	public boolean isErrorMessage() {
		return type<128;
	}
	
	/** Gets an IPv6 packet containing this ICMP message.
	 * @return the IPv6 packet */
	public Ip6Packet toIp6Packet() {
		return new Ip6Packet((Ip6Address)getSourceAddress(),(Ip6Address)getDestAddress(),Ip6Packet.IPPROTO_ICMP6,getBytes());
	}
	
	@Override
	public int getPacketLength() {
		return 4+icmp_body.length;
	}

	@Override
	public byte[] getBytes() {
		int len=getPacketLength();
		byte[] buf=new byte[len];
		getBytes(buf,0);
		return buf;
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		buf[off]=(byte)type; // type
		buf[off+1]=(byte)code; // code
		buf[off+2]=(byte)0; // checksum
		buf[off+3]=(byte)0; // checksum
		System.arraycopy(icmp_body,0,buf,off+4,icmp_body.length);
		int icmp_len=4+icmp_body.length;
		int checksum=Checksum.transportChecksum6(src_addr.getBytes(),dst_addr.getBytes(),Ip6Packet.IPPROTO_ICMP6,buf,off,icmp_len);
		ByteUtils.intToTwoBytes(checksum,buf,off+2);
		return icmp_len;
	}

	@Override
	public Object clone() {
		Icmp6Message pkt;
		try {
			pkt=(Icmp6Message)super.clone();
			pkt.icmp_body=new byte[icmp_body.length];
			System.arraycopy(icmp_body,0,pkt.icmp_body,0,icmp_body.length);
			return pkt;
		}
		catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@Override
	public String toString() {
		//return "src="+src_addr+", dst="+dst_addr+", type="+type+", code="+code+", msglen="+getPacketLength();
		return "ICMPv6 "+src_addr+" > "+dst_addr+" type="+type+" code="+code+" msglen="+getPacketLength();
	}

}
