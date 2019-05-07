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

package it.unipr.netsec.ipstack.ip4;


import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.net.DataPacket;
import it.unipr.netsec.ipstack.util.Checksum;


/** Internet Protocol version 4 (IPv4) packet (RFC 791).
  */
public class Ip4Packet extends DataPacket {
	
	/** Version */
	private static final int VERSION=4;

	/** Maximum packet size */
	public static int MAXIMUM_PACKET_SIZE=65535;

	/** Default TTL */
	public static int DEFAULT_TTL=128;

	
	// Some standard IP protocols:
	
	/** Internet Protocol (IP) */
	public static final int IPPROTO_IP=0;
	/** IP in IP (IPIP) encapsulation */
	public static final int IPPROTO_IPIP=4;
	/** Internet Protocol version 6 (IPv6) */
	public static final int IPPROTO_IPV6=41;
	/** Internet Control Message Protocol (ICMP) */
	public static final int IPPROTO_ICMP=1;
	/** Internet Group Management Protocol */
	public static final int IPPROTO_IGMP=2;
	/** Transmission Control Protocol (TCP) */
	public static final int IPPROTO_TCP=6;
	/** User Datagram Protocol (UDP) */
	public static final int IPPROTO_UDP=17;
	/** Stream Control Transport Protocol (SCTP) */
	public static final int IPPROTO_SCTP=132;
	/** Authentication Header (AH) protocol */
	public static final int IPPROTO_AH=51;
	/** Encapsulation Security Payload (ESP) protocol */
	public static final int IPPROTO_ESP=50;
	/** Open Shortest Path First (OSPF) protocol */
	public static final int IPPROTO_OSPF=89;
	/** Raw IP Packets */ 
	public static final int IPPROTO_RAW=255;


	// Some standard IPv4 options:

	/** IPv4 Option, End of options list (RFC 791). */
	public static final int IP4OPT_END_OPTS_LIST=0;
	/** IPv4 Option, NOP (RFC 791). */
	public static final int IP4OPT_NOP=1;

	
	// IPv4 header offsets:

	/** IP header offset of TOS field */
	private static final int IPH_OFF_TOS=1;
	/** IP header offset of packet length field */
	private static final int IPH_OFF_PLEN=2;
	/** IP header offset of fragment identifier field */
	private static final int IPH_OFF_ID=4;
	/** IP header offset of fragment flags and offset field */
	private static final int IPH_OFF_FRAGM=6;
	/** IP header offset of TTL field */
	private static final int IPH_OFF_TTL=8;
	/** IP header offset of protocol field */
	private static final int IPH_OFF_PROTO=9;
	/** IP header offset of checksum field */
	private static final int IPH_OFF_CHKSUM=10;
	/** IP header offset of src address */
	private static final int IPH_OFF_SRC=12;
	/** IP header offset of dest address */
	private static final int IPH_OFF_DST=16;
	/** IP header offset of options field */
	private static final int IPH_OFF_OPTS=20;


	// IPv4 packet additional attributes:
	
	/** Type of Service (TOS) (8 bit) */
	int tos=0;
	
	/** Packet id (16 bit) */
	int id=0;
	
	/** Reserved flag (bit 0 of flags field) */
	//boolean reserved_flag=false;

	/** Don't Fragment (DF) flag (bit 1 of flags field) */
	boolean dont_fragment=false;
	
	/** More Fragments (MF) flag (bit 2 of flags field) */
	boolean more_fragments=false;
	
	/** Fragment offset (13 bit) */
	int fragment_off=0;

	/** Time To Live (TTL) (8 bit) */
	int ttl=DEFAULT_TTL;

	/** Payload type (8 bit) */
	int proto=0;
	
	/** Checksum (16 bit) */
	int checksum=0;
	
	/** IP options buffer */
	byte[] options_buf=null;
	
	/** IP options offset within the buffer */
	int options_off=0;
	
	/** IP options length */
	int options_len=0;

	

	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param proto payload type
	 * @param data the packet payload */
	public Ip4Packet(Ip4Address src_addr, Ip4Address dst_addr, int proto, byte[] data) {
		super(src_addr,dst_addr,data);
		setProto(proto);
	}

	
	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param proto payload type
	 * @param data_buf the buffer containing the packet payload
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public Ip4Packet(Ip4Address src_addr, Ip4Address dst_addr, int proto, byte[] data_buf, int data_off, int data_len) {
		super(src_addr,dst_addr,data_buf,data_off,data_len);
		setProto(proto);
	}

	
	/** Gets Type-of-Service (TOS) field.
	 * @return TOS value */
	public int getTOS() {
		return ttl;
	}

	/** Sets Type-of-Service (TOS) field.
	 * @param tos the TOS value */
	public void setTOS(int tos) {
		this.tos=tos;
	}

	/** Gets packet identifier field.
	 * @return id value */
	public int getID() {
		return id;
	}

	/** Sets packet identifier field.
	 * @param id the id value */
	public void setID(int id) {
		this.id=id;
	}

	/** Gets Don't Fragment (DF) flag.
	 * @return DF flag value */
	public boolean getDontFragmentFlag() {
		return dont_fragment;
	}

	/** Sets Don't Fragment (DF) flag.
	 * @param dont_fragment DF flag value */
	public void setDontFragmentFlag(boolean dont_fragment) {
		this.dont_fragment=dont_fragment;
	}
	
	/** Gets More Fragments (MF) flag.
	 * @return MF flag value */
	public boolean getMoreFragmentsFlag() {
		return more_fragments;
	}

	/** Sets More Fragments (MF) flag.
	 * @param more_fragments MF flag value */
	public void setMoreFragmentsFlag(boolean more_fragments) {
		this.more_fragments=more_fragments;
	}
	
	/** Gets fragment offset.
	 * @return fragment offset */
	public int getFragmentOffset() {
		return fragment_off;
	}

	/** Sets fragment offset.
	 * @param fragment_off fragment offset */
	public void setFragmentOffset(int fragment_off) {
		this.fragment_off=fragment_off;
	}

	/** Gets Time-To-Live (TTL) field.
	 * @return TTL value */
	public int getTTL() {
		return ttl;
	}

	/** Sets Time-To-Live (TTL) field.
	 * @param ttl the TTL value */
	public void setTTL(int ttl) {
		this.ttl=ttl;
	}

	/** Gets IP protocol field.
	 * @return protocol */
	public int getProto() {
		return proto;
	}

	/** Sets IP protocol field.
	 * @param proto the protocol */
	public void setProto(int proto) {
		this.proto=proto;
	}

	/** Gets checksum field.
	 * @return checksum */
	public int getChecksum() {
		return checksum;
	}

	/** Sets checksum field.
	 * @param checksum the checksum value */
	private void setChecksum(int checksum) {
		this.checksum=checksum;
	}

	/** Sets IP options.
	 * @param options the IP options field */
	public void setOptions(byte[] options) {
		setOptions(options,0,options.length);
	}
	 
	/** Sets IP options.
	 * @param options_buf the buffer containing IP options field
	 * @param options_off the offset within the buffer 
	 * @param options_len the length of the options field */
	public void setOptions(byte[] options_buf, int options_off, int options_len) {
		this.options_buf=options_buf;
		this.options_off=options_off;
		this.options_len=options_len;
	}
		
	/** Sets IP options length.
	 * @param len the length of the options field */
	public void setOptionsLength(int len) {
		this.options_len=len;
	}
	
	/** Whether there are any IP options.
	 * @return <pre>true</pre> if there is the IP options field */
	public boolean hasOptions() {
		return options_buf!=null && options_len>0;
	}

	/** Gets IP options buffer.
	 * @return the buffer containing the IP options field */
	public byte[] getOptionsBuffer() {
		return options_buf;
	}

	/** Gets IP options offset within the buffer.
	 * @return a the offset within the buffer containing the IP options field */
	public int getOptionsOffset() {
		return options_off;
	}
	
	/** Gets IP options length.
	 * @return a the length of the IP options field */
	public int getOptionsLength() {
		return options_len;
	}
	
	/** Gets IP options.
	 * @return the IP options field */
	/*public byte[] getOptions() {
		return options;
	}*/

	
	@Override
	public int getPacketLength() {
		int hlen=options_len/4 + 5;
		return hlen*4+data_len;
	}
	
	
	@Override
	public int getBytes(byte[] buf, int off) {
		int index=off;
		int hlen=options_len/4 + 5;
		int total_len=hlen*4+data_len;
		buf[index++]=(byte)((VERSION<<4)|(hlen&0x0f)); // V + HLEN
		buf[index++]=(byte)tos; // TOS
		buf[index++]=(byte)((total_len & 0xff00)>>8); // LEN
		buf[index++]=(byte)((total_len & 0xff)); // LEN
		buf[index++]=(byte)((id&0xff00)>>8); // ID
		buf[index++]=(byte)(id&0xff);
		buf[index++]=(byte)((dont_fragment?0x40:0x00) | (more_fragments?0x20:0x00) | ((fragment_off&0x1f00)>>8)); // FLAGS + FRAG OFF
		buf[index++]=(byte)(fragment_off&0x00ff); // FRAG OFF
		buf[index++]=(byte)ttl; // TTL
		buf[index++]=(byte)proto; // PROTO
		buf[index++]=0; // CHECKSUM 0
		buf[index++]=0; // CHECKSUM 0
		if (options_buf!=null) System.arraycopy(options_buf,options_off,buf,index,options_len);
		index+=options_len;
		while ((index-off)%4!=0) buf[index++]=0; //OPT_PAD
		//Ip4Address.stringToBytes(src_addr,buf,index); index+=4; // SRC_ADDR
		//Ip4Address.stringToBytes(dst_addr,buf,index); index+=4; // DST_ADDR
		System.arraycopy(((Ip4Address)src_addr).getBytes(),0,buf,index,4); index+=4; // SRC_ADDR
		System.arraycopy(((Ip4Address)dst_addr).getBytes(),0,buf,index,4); index+=4; // DST_ADDR
		if (data_len>0) System.arraycopy(data_buf,data_off,buf,off+20,data_len);

		// compute the checksum
		checksum=Checksum.checksum(buf,off,hlen*4);
		buf[off+IPH_OFF_CHKSUM]=(byte)((checksum & 0xff00)>>8);
		buf[off+IPH_OFF_CHKSUM+1]=(byte)((checksum & 0xff));
		
		return total_len;
	}

	
	/** Parses the given raw data (array of bytes) for an IPv4 packet.
	 * @param buf the buffer containing the IP packet
	 * @return the IP packet */
	public static Ip4Packet parseIp4Packet(byte[] buf) {
		return parseIp4Packet(buf,0,buf.length);
	}

	
	/** Parses the given raw data (array of bytes) for an IPv4 packet.
	 * @param buffer the buffer containing the IP packet
	 * @param offset the offset within the buffer
	 * @param maxlen maximum number of bytes that can be processed
	 * @return the IP packet */
	public static Ip4Packet parseIp4Packet(byte[] buffer, int offset, int maxlen) {
		int version=(buffer[offset]&0xf0)>>4;
		if (version!=4) new RuntimeException("Wrong IP version: "+version);
		int hdr_len=(buffer[offset]&0x0f)<<2; // *4
		int tos=buffer[offset+IPH_OFF_TOS]&0xff;
		int pkt_len=((buffer[offset+IPH_OFF_PLEN]&0xff)<<8) + (buffer[offset+IPH_OFF_PLEN+1]&0xff);
		int id=(buffer[offset+IPH_OFF_ID]&0xff)<<8 + (buffer[offset+IPH_OFF_ID+1]&0xff);
		boolean dont_fragment=(buffer[offset+IPH_OFF_FRAGM]&0x40)!=0;
		boolean more_fragments=(buffer[offset+IPH_OFF_FRAGM]&0x20)!=0;
		int fragment_off=(((buffer[offset+IPH_OFF_FRAGM]&0x1f)<<8) +(buffer[offset+IPH_OFF_FRAGM+1]&0xff))<<2; // *4
		int ttl=buffer[offset+IPH_OFF_TTL]&0xff;
		int proto=buffer[offset+IPH_OFF_PROTO]&0xff;
		int checksum=((buffer[offset+IPH_OFF_CHKSUM]&0xff)<<8) + (buffer[offset+IPH_OFF_CHKSUM+1]&0xff);
		// options
		byte[] options_buf=buffer;
		int options_off=offset+IPH_OFF_OPTS;
		int options_len=hdr_len-IPH_OFF_OPTS;
		// addresses
		//String src_addr=Ip4Address.bytesToString(buffer,offset+IPH_OFF_SRC);
		//String dst_addr=Ip4Address.bytesToString(buffer,offset+IPH_OFF_DST);
		Ip4Address src_addr=new Ip4Address(buffer,offset+IPH_OFF_SRC);
		Ip4Address dst_addr=new Ip4Address(buffer,offset+IPH_OFF_DST);
		// payload data
		byte[] data_buf=buffer;
		int data_off=offset+hdr_len;
		int data_len=pkt_len-hdr_len;
		if (data_len>maxlen) new RuntimeException("Length field exceeds the number of available bytes");
		Ip4Packet ip_packet=new Ip4Packet(src_addr,dst_addr,proto,data_buf,data_off,data_len);
		ip_packet.setTOS(tos);
		ip_packet.setID(id);
		ip_packet.setDontFragmentFlag(dont_fragment);
		ip_packet.setMoreFragmentsFlag(more_fragments);
		ip_packet.setFragmentOffset(fragment_off);
		ip_packet.setTTL(ttl);
		ip_packet.setChecksum(checksum);
		if (options_len>0) ip_packet.setOptions(options_buf,options_off,options_len);
		return ip_packet;
	}

	
	/** Parses an Ethernet packet for an IP packet.
	 * @param eth_pkt Ethernet packet containing the IP packet
	 * @return the IP packet */
	public static Ip4Packet parseIp4Packet(EthPacket eth_pkt) {
		return parseIp4Packet(eth_pkt.getPayloadBuffer(),eth_pkt.getPayloadOffset(),eth_pkt.getPayloadLength());
	}

		
	@Override
	public String toString() {
		//return "src="+src_addr+", dst="+dst_addr+", ttl="+ttl+", proto="+proto+", datalen="+getPayloadLength();
		return "IP "+src_addr+" > "+dst_addr+" ttl="+ttl+" proto="+proto+" datalen="+getPayloadLength();
	}

	
	/** Updates IPv4 header checksum within the given IPv4 header.
	 * @param buf the buffer containing the IPv4 header
	 * @param off the offset of the IPv4 header within the buffer */
	/*public static void updateIPv4HeaderChecksum(byte[] buf, int off) {
		int hlen=4*(buf[off]&0x0F);
		BinUtils.intToTwoBytes(0,buf,off+IPH_OFF_CHKSUM);
		int checksum=checksum(buf,off,hlen);
		BinUtils.intToTwoBytes(checksum,buf,off+IPH_OFF_CHKSUM);
	}*/

}
