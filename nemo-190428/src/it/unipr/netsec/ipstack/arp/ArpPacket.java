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

package it.unipr.netsec.ipstack.arp;


import java.util.Arrays;

import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;


/** Address Resolution Protocol (ARP) packet.
 */
public class ArpPacket implements Packet {

	/** Request operation */
	public static final int ARP_REQUEST=1;
			
	/** Reply operation */
	public static final int ARP_REPLY=2;
	
	/** Hardware type Ethernet */
	public static final int HARDWARE_TYPE_ETH=1;
	
	/** Protocol type IPv4 */
	public static final int PROTOCOL_TYPE_IP4=0x800;

	
	/** Source address */
	protected Address src_addr;
	
	/** Destination address  */
	protected Address dst_addr;

	/** Hardware type (HTYPE). This field specifies the network protocol type. Example: Ethernet is 1 */
	protected int htype;
	
	/** Protocol type (PTYPE). This field specifies the internetworking protocol for which the ARP request is intended. For IPv4, this has the value 0x0800. The permitted PTYPE values share a numbering space with those for EtherType */
	protected int ptype;
	
	/** Hardware length (HLEN). Length (in octets) of a hardware address. Ethernet addresses size is 6 */
	protected int hlen;
	
	/** Protocol length (PLEN). Length (in octets) of addresses used in the upper layer protocol. (The upper layer protocol specified in PTYPE.) IPv4 address size is 4 */
	protected int plen;
	
	/** Operation. Specifies the operation that the sender is performing: 1 for request, 2 for reply */
	protected int operation;
	
	/** Sender hardware address (SHA). Media address of the sender */
	protected byte[] sha;
	
	/** Sender protocol address (SPA). Internetwork address of the sender */
	protected byte[] spa;
	
	/** Target hardware address (THA). Media address of the intended receiver. In an ARP request this field is ignored. In an ARP reply this field is used to indicate the address of the host that originated the ARP request */
	protected byte[] tha;
	
	/** Target protocol address (TPA). Internetwork address of the intended receiver */
	protected byte[] tpa;
	

	/** Creates a new ARP packet.
	 * @param src_addr source address (<i>null</i> if unknown)
	 * @param src_addr source address
	 * @param htype data-link hardware protocol type. Example: Ethernet is 1
	 * @param ptype network protocol for which the ARP request is intended. For IPv4, this has the value 0x0800
	 * @param hlen length (in octets) of a hardware address. Ethernet addresses size is 6
	 * @param plen length (in octets) of addresses used in the upper layer protocol. (The upper layer protocol specified in PTYPE.) IPv4 address size is 4
	 * @param operation operation that the sender is performing: 1 for request, 2 for reply
	 * @param sha sender data-link hardware address
	 * @param spa sender network protocol address
	 * @param tha target data-link hardware address
	 * @param tpa target network protocol address */
	public ArpPacket(Address src_addr, Address dst_addr, int htype, int ptype, int hlen, int plen, int operation, byte[] sha, byte[] spa, byte[] tha, byte[] tpa) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.htype=htype;
		this.ptype=ptype;
		this.hlen=hlen;
		this.plen=plen;
		this.operation=operation;
		this.sha=sha;
		this.spa=spa;
		this.tha=tha;
		this.tpa=tpa;
	}

	/** Creates a new ARP packet.
	 * @param src_addr source address (<i>null</i> if unknown)
	 * @param src_addr source address
	 * @param operation operation that the sender is performing: 1 for request, 2 for reply
	 * @param shaddr sender data-link hardware address
	 * @param spaddr sender network protocol address
	 * @param thaddr target data-link hardware address
	 * @param tpaddr target network protocol address */
	public ArpPacket(Address src_addr, Address dst_addr, int operation, EthAddress shaddr, Ip4Address spaddr, EthAddress thaddr, Ip4Address tpaddr) {
		this(src_addr,dst_addr,HARDWARE_TYPE_ETH,PROTOCOL_TYPE_IP4,6,4,operation,shaddr!=null?shaddr.getBytes():null,spaddr.getBytes(),thaddr!=null?thaddr.getBytes():null,tpaddr.getBytes());
	}

	/** Gets the hardware type.
	 * @return the type */
	public int getHtype() {
		return htype;
	}
		
	/** Gets the network protocol type.
	 * @return the type */
	public int getPtype() {
		return ptype;
	}

	/** Gets the hardware address length.
	 * @return the length in octects */
	public int getHlen() {
		return hlen;
	}

	/** Gets the network protocol address length.
	 * @return the the length in octects */
	public int getPlen() {
		return plen;
	}

	/** Gets the operation that the sender is performing
	 * @return the operation; 1 for request, 2 for reply */
	public int getOperation() {
		return operation;
	}

	/** Gets the hardware address of the sender
	 * @return the address */
	public byte[] getSenderHardwareAddress() {
		return sha;
	}

	/** Gets the network protocol address of the sender
	 * @return the address */
	public byte[] getSenderProtocolAddress() {
		return spa;
	}

	/** Gets the hardware address of the target
	 * @return the address */
	public byte[] getTargetHardwareAddress() {
		return tha;
	}

	/** Gets the protocol address of the target
	 * @return the address */
	public byte[] getTargetProtocolAddress() {
		return tpa;
	}

	@Override
	public Address getSourceAddress() {
		/*switch (ptype) {
			case PROTOCOL_TYPE_IP4 : return new Ip4Address(spa);
			default : throw new RuntimeException("network address type "+ptype+" not supported.");
		}*/
		return src_addr;
	}

	@Override
	public Address getDestAddress() {
		/*switch (ptype) {
			case PROTOCOL_TYPE_IP4 : return new Ip4Address(tpa);
			default : throw new RuntimeException("network address type "+ptype+" not supported.");
		}*/
		return dst_addr;
	}

	@Override
	public int getPacketLength() {
		return 28;
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		ByteUtils.intToTwoBytes(htype,buf,0);
		ByteUtils.intToTwoBytes(ptype,buf,2);
		buf[off+4]=(byte)(hlen&0xff);
		buf[off+5]=(byte)(plen&0xff);
		ByteUtils.intToTwoBytes(operation,buf,6);
		copyAndFill(sha,0,hlen,buf,8,6);
		copyAndFill(spa,0,plen,buf,14,4);
		copyAndFill(tha,0,hlen,buf,18,6);
		copyAndFill(tpa,0,plen,buf,24,4);		
		return 28;
	}
	
	@Override
	public byte[] getBytes() {
		byte[] buf=new byte[28];
		getBytes(buf,0);
		return buf;
	}
	
	/** Parses the given raw data (array of bytes) for an ARP packet.
	 * @param src_addr source address
	 * @param src_addr source address
	 * @param buf the buffer containing the packet
	 * @param off the offset within the buffer
	 * @param len packet length
	 * @return the ARP packet */
	public static ArpPacket parseArpPacket(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		int htype=ByteUtils.twoBytesToInt(buf,off+0);
		int ptype=ByteUtils.twoBytesToInt(buf,off+2);
		int hlen=buf[off+4]&0xff;
		int plen=buf[off+5]&0xff;
		int operation=ByteUtils.twoBytesToInt(buf,off+6);
		byte[] sha=ByteUtils.copy(buf,off+8,hlen);
		byte[] spa=ByteUtils.copy(buf,off+14,plen);
		byte[] tha=ByteUtils.copy(buf,off+18,hlen);
		byte[] tpa=ByteUtils.copy(buf,off+24,plen);
		ArpPacket pkt=new ArpPacket(src_addr,dst_addr,htype,ptype,hlen,plen,operation,sha,spa,tha,tpa);
		return pkt;
	}

	/** Parses the given ARP packet.
	 * @param eth_pkt Ethernet frame containing the ARP packet
	 * @return the ARP packet */
	public static ArpPacket parseArpPacket(EthPacket eth_pkt) {
		return parseArpPacket(eth_pkt.getSourceAddress(),eth_pkt.getDestAddress(),eth_pkt.getPayloadBuffer(),eth_pkt.getPayloadOffset(),eth_pkt.getPayloadLength());
	}

	@Override
	public Object clone() {
		try {
			return super.clone();
		}
		catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@Override
	public String toString() {
		String op_str=operation==ARP_REQUEST? " query" : operation==ARP_REPLY? " reply" : " op="+operation;
		String sha_str=sha==null? null : htype==HARDWARE_TYPE_ETH? new EthAddress(sha).toString() : ByteUtils.bytesToHexString(sha);
		String tha_str=tha==null? null : htype==HARDWARE_TYPE_ETH? new EthAddress(tha).toString() : ByteUtils.bytesToHexString(tha);
		String spa_str=spa==null? null : ptype==PROTOCOL_TYPE_IP4? new Ip4Address(spa).toString() : ByteUtils.bytesToHexString(spa);
		String tpa_str=tpa==null? null : ptype==PROTOCOL_TYPE_IP4? new Ip4Address(tpa).toString() : ByteUtils.bytesToHexString(tpa);
		return "ARP "+src_addr+" > "+dst_addr+op_str+" sha="+sha_str+" spa="+spa_str+" tha="+tha_str+" tpa="+tpa_str;
	}

	/** Copies an array of bytes into another array, filling the remaining bytes with the given value.
	 * @param src the buffer containing the source array
	 * @param src_off the offset of the source array
	 * @param src_len the length of the source array
	 * @param dst the buffer containing the destination array
	 * @param dst_off the offset of the destination array
	 * @param dst_len the length of the destination array */
	private static void copyAndFill(byte[] src, int src_off, int src_len, byte[] dst, int dst_off, int dst_len) {
		if (src!=null) {
			System.arraycopy(src,src_off,dst,dst_off,src_len);
			Arrays.fill(dst,dst_off+src_len,dst_off+dst_len,(byte)0);
		}
		else Arrays.fill(dst,dst_off,dst_off+dst_len,(byte)0);
	}

}
