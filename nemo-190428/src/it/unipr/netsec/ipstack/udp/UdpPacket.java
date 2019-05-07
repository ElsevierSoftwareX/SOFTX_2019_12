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

package it.unipr.netsec.ipstack.udp;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.DataPacket;
import it.unipr.netsec.ipstack.util.Checksum;


/** User Datagram Protocol (RFC 768) packet unit.
 */
public class UdpPacket extends DataPacket {	

	/** Source port */
	int src_port;
	
	/** Destination port */
	int dst_port;

	/** Whether the checksum is correct (1), unspecified (0), wrong (-1) */
	int checksum_check=0;

	
	/** Creates a new UDP datagram.
	 * @param src_addr source address
	 * @param src_port source port number
	 * @param dst_addr destination address
	 * @param dst_port destination port number
	 * @param data the packet payload */
	public UdpPacket(IpAddress src_addr, int src_port, IpAddress dst_addr, int dst_port, byte[] data) {
		super(src_addr,dst_addr,data);
		this.src_port=src_port;
		this.dst_port=dst_port;
	}

	/** Creates a new UDP datagram.
	 * @param src_addr source address
	 * @param src_port source port number
	 * @param dst_addr destination address
	 * @param dst_port destination port number
	 * @param data_buf the buffer containing the packet payload
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public UdpPacket(IpAddress src_addr, int src_port, IpAddress dst_addr, int dst_port, byte[] data_buf, int data_off, int data_len) {
		super(src_addr,dst_addr,data_buf,data_off,data_len);
		this.src_port=src_port;
		this.dst_port=dst_port;
	}
	
	/** Parses a UDP datagram.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf buffer containing the UDP packet
	 * @param off the offset within the buffer
	 * @param len the length of the UDP packet */
	public static UdpPacket parseUdpPacket(IpAddress src_addr, IpAddress dst_addr, byte[] buf, int off, int len) {
		int src_port=((buf[off+0]&0xff)<<8) + (buf[off+1]&0xff);
		int dst_port=((buf[off+2]&0xff)<<8) + (buf[off+3]&0xff);
		int pkt_len=((buf[off+4]&0xff)<<8) + (buf[off+5]&0xff);
		if (pkt_len!=len) new RuntimeException("Length field is different from the number of bytes");
		UdpPacket udp_pkt=new UdpPacket(src_addr,src_port,dst_addr,dst_port,buf,off+8,len-8);
		// check checksum
		udp_pkt.checksum_check=0;
		int checksum=((buf[off+6]&0xff)<<8) + (buf[off+7]&0xff);
		if (checksum!=0) {
			checksum=Checksum.transportChecksum4(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_UDP,buf,off,pkt_len) & 0xffff;
			//if (checksum!=0x0000 && checksum!=0xffff) throw new RuntimeException("Wrong UDP checksum");
			if (checksum==0x0000 || checksum==0xffff) udp_pkt.checksum_check=1;
			else udp_pkt.checksum_check=-1;
		}
		return udp_pkt;
	}

	/** Parses a UDP datagram.
	 * @param ip_pkt IPv4 packet containing the UDP packet */
	public static UdpPacket parseUdpPacket(Ip4Packet ip_pkt) {
		IpAddress src_addr=(IpAddress)ip_pkt.getSourceAddress();
		IpAddress dst_addr=(IpAddress)ip_pkt.getDestAddress();
		return parseUdpPacket(src_addr,dst_addr,ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
	}

	/** Parses a UDP packet.
	 * @param ip_pkt IPv6 packet containing the UDP packet */
	public static UdpPacket parseUdpPacket(Ip6Packet ip_pkt) {
		IpAddress src_addr=(IpAddress)ip_pkt.getSourceAddress();
		IpAddress dst_addr=(IpAddress)ip_pkt.getDestAddress();
		return parseUdpPacket(src_addr,dst_addr,ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
	}

	/** Gets the source port number.
	 * @return source port */
	public int getSourcePort() {
		return src_port;
	}

	/** Gets the destination port number.
	 * @return destination port */
	public int getDestPort() {
		return dst_port;
	}

	/** Whether the checksum is correct, unspecified, wrong.
	 * @return 1= correct checksum, 0= unspecified checksum, -1= wrong checksum */
	public int getChecksumCheck() {
		return checksum_check;
	}

	@Override
	public int getPacketLength() {
		return 8+data_len;
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		int index=off;
		int total_len=8+data_len;
		buf[index++]=(byte)((src_port & 0xff00)>>8); // src port
		buf[index++]=(byte)((src_port & 0xff)); // src port
		buf[index++]=(byte)((dst_port & 0xff00)>>8); // dst port
		buf[index++]=(byte)((dst_port & 0xff)); // dst port
		buf[index++]=(byte)((total_len & 0xff00)>>8); // length
		buf[index++]=(byte)((total_len & 0xff)); // length
		buf[index++]=0; // CHECKSUM 0
		buf[index++]=0; // CHECKSUM 0
		if (data_len>0) System.arraycopy(data_buf,data_off,buf,off+8,data_len);
		// compute the checksum
		int checksum=0;
		if (dst_addr instanceof Ip4Address) checksum=Checksum.transportChecksum4(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_UDP,buf,off,total_len);
		else if (dst_addr instanceof Ip6Address) checksum=Checksum.transportChecksum6(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_UDP,buf,off,total_len);
		buf[off+6]=(byte)((checksum & 0xff00)>>8);
		buf[off+7]=(byte)((checksum & 0xff));
		checksum_check=1;	
		return total_len;
	}
	
	/** Gets an IPv4 packet containing this UDP datagram.
	 * @return the IPv4 packet */
	public Ip4Packet toIp4Packet() {
		return new Ip4Packet((Ip4Address)src_addr,(Ip4Address)dst_addr,Ip4Packet.IPPROTO_UDP,getBytes());
	}

	/** Gets an IPv6 packet containing this UDP datagram.
	 * @return the IPv6 packet */
	public Ip6Packet toIp6Packet() {
		return new Ip6Packet((Ip6Address)src_addr,(Ip6Address)dst_addr,Ip6Packet.IPPROTO_UDP,getBytes());
	}

	@Override
	public String toString() {
		//return "src="+src_addr+", dst="+dst_addr+", datalen="+getPayloadLength();
		StringBuffer sb=new StringBuffer();
		sb.append("UDP ");
		sb.append(SocketAddress.toString((IpAddress)src_addr,src_port)).append(" > ").append(SocketAddress.toString((IpAddress)dst_addr,dst_port));
		if (checksum_check<0) sb.append(" [wrong checksum]");
		sb.append(" datalen=").append(getPayloadLength());
		//sb.append(" data=").append(ByteUtils.asHex(getPayloadBuffer(),getPayloadOffset(),getPayloadLength()));
		return sb.toString();	
	}
	
}
