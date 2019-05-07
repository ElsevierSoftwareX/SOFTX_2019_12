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

package it.unipr.netsec.nemo.routing.ospf;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.util.Checksum;


/** OSPF packet.
 */
public class OspfPacket implements Packet {

	/** Hello type */
	public static final int TYPE_Hello=1;

	/** Database Description (DBD) type */
	public static final int TYPE_DBD=2;

	/** Link State Request (LSR) type */
	public static final int TYPE_LSR=3;

	/** Link State Update (LSU) type */
	public static final int TYPE_LSU=4;

	/** Link State Acknowledgment (LSAck) type */
	public static final int TYPE_LSAck=5;
	
	
	/** IP source address */
	protected Address src_addr;
	
	/** IP destination address */
	protected Address dst_addr;
	
	/** Version */
	protected int version;
	
	/** Packet type */
	protected int type;
	
	/** Router ID */
	protected Ip4Address router_id;
	
	/** Area ID */
	protected Ip4Address area_id;
	
	/** Authentication type */
	protected int auth_type;
	
	/** Authentication */
	protected long authentication;

	/** Message body */
	protected byte[] body;

	
	/** Creates a new OSPF packet.
	 * @param pkt the OSPF packet */
	protected OspfPacket(OspfPacket pkt) {
		this(pkt.src_addr,pkt.dst_addr,pkt.type,pkt.router_id,pkt.area_id,pkt.body,0,pkt.body.length);
	}

	/** Creates a new OSPF packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type packet type
	 * @param router_id router ID
	 * @param area_id area ID
	 * @param body the OSPF packet excluding the first 24 bytes */
	public OspfPacket(Address src_addr, Address dst_addr, int type, Ip4Address router_id, Ip4Address area_id, byte[] body) {
		this(src_addr,dst_addr,type,router_id,area_id,body,0,body.length);
	}

	/** Creates a new OSPF packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type packet type
	 * @param router_id router ID
	 * @param area_id area ID
	 * @param buf buffer containing the OSPF packet excluding the first 24 bytes
	 * @param off the offset within the buffer
	 * @param len the length of the OSPF packet minus 24 */
	public OspfPacket(Address src_addr, Address dst_addr, int type, Ip4Address router_id, Ip4Address area_id, byte[] buf, int off, int len) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.type=type;
		this.router_id=router_id;
		this.area_id=area_id;
		this.body=new byte[len];
		System.arraycopy(buf,off,body,0,len);		
	}

	/** Creates a new OSPF packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf buffer containing the OSPF packet
	 * @param off the offset within the buffer
	 * @param len the length of the OSPF packet */
	public OspfPacket(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		version=buf[off]&0xff;
		type=buf[off+1]&0xff;
		int length=ByteUtils.twoBytesToInt(buf,off+2);
		if (length!=len) throw new RuntimeException("Wrong OSPF packet length: OSPF packet from "+src_addr+" to "+dst_addr+": "+ByteUtils.bytesToHexString(buf,off,len));
		router_id=new Ip4Address(buf,off+4);
		area_id=new Ip4Address(buf,off+8);
		authentication=ByteUtils.eightBytesToInt(buf,off+16);
		int checksum=Checksum.checksum(buf,off,len) & 0xffff;
		if (checksum!=0x0000 && checksum!=0xffff) throw new RuntimeException("Wrong OSPF checksum: OSPF packet from "+src_addr+" to "+dst_addr+": "+ByteUtils.bytesToHexString(buf,off,len));
		// else
		body=new byte[len-24];
		System.arraycopy(buf,off+24,body,0,body.length);
	}

	/** Creates a new OSPF packet.
	 * @param ip_pkt IP packet containing the OSPF packet */
	public OspfPacket(Ip4Packet ip_pkt) {
		this(ip_pkt.getSourceAddress(),ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
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

	/** Gets the packet type.
	 * @return the type */
	public int getType() {
		return type;
	}
	
	/** Gets the router ID.
	 * @return the ID */
	public Ip4Address getRouterID() {
		return router_id;
	}

	/** Gets the area ID.
	 * @return the ID */
	public Ip4Address getAreaID() {
		return area_id;
	}

	/** Gets the authentication type.
	 * @return the type */
	public int getAuthType() {
		return auth_type;
	}

	/** Gets the authentication field.
	 * @return the authentication field */
	public long getAuthnetication() {
		return authentication;
	}

	/** Gets an IP packet containing this OSPF packet.
	 * @return the IP packet */
	public Ip4Packet toIp4Packet() {
		return new Ip4Packet((Ip4Address)getSourceAddress(),(Ip4Address)getDestAddress(),Ip4Packet.IPPROTO_OSPF,getBytes());
	}

	@Override
	public int getPacketLength() {
		return 24+body.length;
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
		buf[off]=(byte)2; // type
		buf[off+1]=(byte)type; // type
		int len=24+body.length;
		ByteUtils.intToTwoBytes(len,buf,2);
		router_id.getBytes(buf,4);
		area_id.getBytes(buf,8);
		buf[off+12]=(byte)0;
		buf[off+13]=(byte)0;
		ByteUtils.intToTwoBytes(auth_type,buf,14);
		ByteUtils.intToEightBytes(authentication,buf,16);
		System.arraycopy(body,0,buf,off+24,body.length);
		int checksum=Checksum.checksum(buf,off,len);
		ByteUtils.intToTwoBytes(checksum,buf,off+12);
		return len;
	}
	
	@Override
	public Object clone() {
		OspfPacket pkt;
		try {
			pkt=(OspfPacket)super.clone();
			pkt.body=new byte[body.length];
			System.arraycopy(body,0,pkt.body,0,body.length);
			return pkt;
		}
		catch (CloneNotSupportedException e) {
			return null;
		}
	}

	
	@Override
	public String toString() {
		return "OSPF "+src_addr+" > "+dst_addr+" type="+type+" router_id="+router_id+" area_id="+area_id+" len="+getPacketLength();
	}

}
