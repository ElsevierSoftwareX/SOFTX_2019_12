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

package it.unipr.netsec.ipstack.icmp4;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.util.Checksum;


/** ICMP (Internet Control Message Protocol) packet.
 */
public class IcmpMessage implements Packet {

	/** ICMP Type: Echo Reply */
	public static final int TYPE_Echo_Reply=0;

	/** ICMP Type: Destination Unreachable */
	public static final int TYPE_Destination_Unreachable=3;

	/** ICMP Type: Source Quench */
	public static final int TYPE_Source_Quench=4;

	/** ICMP Type: Redirect */
	public static final int TYPE_Redirect=5;

	/** ICMP Type: Echo Request */
	public static final int TYPE_Echo_Request=8;

	/** ICMP Type: Router Advertisement */
	public static final int TYPE_Router_Advertisement=9;

	/** ICMP Type: Router Solicitation */
	public static final int TYPE_Router_Solicitation=10;

	/** ICMP Type: Time Exceeded */
	public static final int TYPE_Time_Exceeded=11;

	/** ICMP Type: Parameter Problem: Bad IP header */
	public static final int TYPE_Parameter_Problem=12;

	/** ICMP Type: Timestamp */
	public static final int TYPE_Timestamp=13;

	/** ICMP Type: Timestamp Reply */
	public static final int TYPE_Timestamp_Reply=14;

	/** ICMP Type: Information Request */
	public static final int TYPE_Information_Request=15;

	/** ICMP Type: Information Reply */
	public static final int TYPE_Information_Reply=16;

	/** ICMP Type: Address Mask Request */
	public static final int TYPE_Address_Mask_Request=17;

	/** ICMP Type: Address Mask Reply */
	public static final int TYPE_Address_Mask_Reply=18;

	/** ICMP Type: Traceroute */
	public static final int TYPE_Traceroute=30;

	
	
	/** IP source address */
	protected Address src_addr;
	
	/** IP destination address */
	protected Address dst_addr;
	
	/** ICMP type */
	protected int type;
	
	/** ICMP subtype code */
	protected int code;
	
	/** Error checking data, calculated from the ICMP header and data, with value 0 substituted for this field */
	//protected int checksum;
	
	/** The ICMP message body, that is the ICMP message excluding the first 4 bytes */
	protected byte[] icmp_body;

	/** Buffer containing the ICMP packet excluding the first 4 bytes */
	//protected byte[] data_buf;

	/** The offset within the buffer */
	//protected int data_off;

	/** The length of the ICMP packet minus 4 */
	//protected int data_len;

	
	
	/** Creates a new ICMP packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code */
	protected IcmpMessage(Address src_addr, Address dst_addr, int type, int code) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.type=type;
		this.code=code;
		icmp_body=null;
	}


	/** Creates a new ICMP packet.
	 * @param msg the ICMP packet */
	protected IcmpMessage(IcmpMessage msg) {
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
	public IcmpMessage(Address src_addr, Address dst_addr, int type, int code, byte[] buf, int off, int len) {
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
	public IcmpMessage(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		init(src_addr,dst_addr,buf,off,len);
	}


	/** Creates a new ICMP packet.
	 * @param ip_pkt IP packet containing the ICMP packet */
	public IcmpMessage(Ip4Packet ip_pkt) {
		init(ip_pkt.getSourceAddress(),ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
	}


	/** Initializes the ICMP packet based on the raw ICMP packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf buffer containing the ICMP packet
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP packet */
	public void init(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		type=buf[off]&0xff;
		code=buf[off+1]&0xff;
		int checksum=Checksum.checksum(buf,off,len) & 0xffff;
		//if (checksum!=0x0000 && checksum!=0xffff) throw new RuntimeException("Wrong ICMP checksum");
		if (checksum!=0x0000 && checksum!=0xffff) throw new RuntimeException("Wrong ICMP checksum: ICMP packet from "+src_addr+" to "+dst_addr+": "+ByteUtils.bytesToHexString(buf,off,len));
		// else
		icmp_body=new byte[len-4];
		System.arraycopy(buf,off+4,icmp_body,0,icmp_body.length);
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


	/** Gets an IP packet containing this ICMP message.
	 * @return the IP packet */
	public Ip4Packet toIp4Packet() {
		return new Ip4Packet((Ip4Address)getSourceAddress(),(Ip4Address)getDestAddress(),Ip4Packet.IPPROTO_ICMP,getBytes());
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
		int checksum=Checksum.checksum(buf,off,icmp_len);
		ByteUtils.intToTwoBytes(checksum,buf,off+2);
		return icmp_len;
	}

	
	@Override
	public Object clone() {
		IcmpMessage pkt;
		try {
			pkt=(IcmpMessage)super.clone();
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
		if (type==TYPE_Echo_Request || type==TYPE_Echo_Reply) {
			int sqn=ByteUtils.twoBytesToInt(icmp_body,2);
			return "ICMP "+src_addr+" > "+dst_addr+" type="+type+" sqn="+sqn+" msglen="+getPacketLength();
		}
		else return "ICMP "+src_addr+" > "+dst_addr+" type="+type+" code="+code+" msglen="+getPacketLength();
	}

}
