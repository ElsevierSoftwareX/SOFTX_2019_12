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

package it.unipr.netsec.ipstack.ethernet;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.DataPacket;


/** An Ethernet packet (IEEE 802.3).
  */
public class EthPacket extends DataPacket {
	
	/** Maximum packet length */
	//public static int MAXIMUM_PAYLOAD_SIZE=1500; // standard frames
	public static int MAXIMUM_PAYLOAD_SIZE=9000; // jumbo frames

	/** Internet Protocol version 4 (IPv4) */
	public static final int ETH_IP4=0x0800;
	
	/** Address Resolution Protocol (ARP) */
	public static final int ETH_ARP=0x0806;

	/** Reverse Address Resolution Protocol */
	public static final int ETH_RARP=0x8035;
	
	/** AppleTalk (Ethertalk) */
	public static final int ETH_ETHTALK=0x0806;
	
	/** VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq */
	public static final int ETH_802_1Q=0x8100;
	
	/** Internet Protocol Version 6 (IPv6) */
	public static final int ETH_IP6=0x86DD;
	
	/** MPLS unicast */
	public static final int ETH_MPLS=0x8847;
	
	/** MPLS multicast */
	public static final int ETH_MPLS_MULTICAST=0x8848;
	
	/** PPPoE Discovery Stage */
	public static final int ETH_PPPoE_DISCOVERY=0x8863;
	
	/** PPPoE Session Stage */
	public static final int ETH_PPPoE=0x8864;
	
	/** EAP over LAN (IEEE 802.1X) */
	public static final int ETH_EAP=0x888E;

	/** Provider Bridging (IEEE 802.1ad) and Shortest Path Bridging IEEE 802.1aq */
	public static final int ETH_802_1AD=0x88A8;

	/** Link Layer Discovery Protocol (LLDP) */
	public static final int ETH_LLDP=0x88CC;

	/** Precision Time Protocol (PTP) over Ethernet */
	public static final int ETH_PTP=0x88F7;	
	
	/** Minimum Ethernet payload length */
	protected static final int MIN_PAYLOAD_LEN=46;	

	
	/** Ethernet type */
	int type;

	/** Input interface associated to this packet */
	//EthAddress in_interface=null;

	/** Output interface associated to this packet */
	String out_interface=null;


	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param type the Ethernet (payload) type
	 * @param data the payload data */
	public EthPacket(Address src_addr, Address dst_addr, int type, byte[] data) {
		super(src_addr,dst_addr,data);
		this.type=type;
	}
	
	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param type the Ethernet (payload) type
	 * @param data_buf the buffer containing the payload data
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public EthPacket(Address src_addr, Address dst_addr, int type, byte[] data_buf, int data_off, int data_len) {
		super(src_addr,dst_addr,data_buf,data_off,data_len);
		this.type=type;
	}
	
	/** Gets Ethernet type.
	 * @return the type */
	public int getType() {
		return type;
	}

	/** Sets Ethernet type.
	 * @param type the type */
	public void setType(int type) {
		this.type=type;
	}

	/** Gets the input interface associated to this packet.
	 * @return the input interface */
	/*public EthAddress getInInterface() {
		return in_interface;
	}*/

	/** Sets the input interface for this packet.
	 * @param in_interface the input interface */
	/*public void setInInterface(EthAddress in_interface) {
		this.in_interface=in_interface;
	}*/
	
	/** Gets the output interface associated to this packet.
	 * @return the output interface */
	public String getOutInterface() {
		return out_interface;
	}

	/** Sets the output interface for this packet.
	 * @param out_interface the output interface */
	public void setOutInterface(String out_interface) {
		this.out_interface=out_interface;
	}
	
	@Override
	public int getPacketLength() {
		//return 14+data_len;
		if (data_len>=MIN_PAYLOAD_LEN) return 14+data_len;
		else return 14+MIN_PAYLOAD_LEN;
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		int index=off;
		//Packet.hexStringToBytes(getDestAddress().toString(),buf,index);
		System.arraycopy(((EthAddress)dst_addr).addr,0,buf,index,6);
		index+=6;
		//Packet.hexStringToBytes(getSourceAddress().toString(),buf,index);	
		System.arraycopy(((EthAddress)src_addr).addr,0,buf,index,6);
		index+=6;
		buf[index++]=(byte)((type&0xff00)>>8);
		buf[index++]=(byte)(type&0xff);
		if (data_len>0) System.arraycopy(data_buf,data_off,buf,index,data_len);
		//return 14+data_len;
		if (data_len>=MIN_PAYLOAD_LEN) return 14+data_len;
		else {
			ByteUtils.fill(buf,index+data_len,MIN_PAYLOAD_LEN-data_len,(byte)0x00);
			return 14+MIN_PAYLOAD_LEN;
		}
	}
	
	
	/** Parses the given raw data (array of bytes) for an Ethernet packet.
	 * @param buf the buffer containing the packet
	 * @return the Ethernet packet */
	public static EthPacket parseEthPacket(byte[] buf) {
		return parseEthPacket(buf,0,buf.length);
	}

	/** Parses the given raw data (array of bytes) for an Ethernet packet.
	 * @param buf the buffer containing the packet
	 * @param off the offset within the buffer
	 * @param len packet length
	 * @return the Ethernet packet */
	public static EthPacket parseEthPacket(byte[] buf, int off, int len) {
		if (len<14 || len>MAXIMUM_PAYLOAD_SIZE+14) throw new RuntimeException("Invalid packet length: "+len);
		//String dst_addr=Packet.bytesToHexString(buf,off,6);
		//String src_addr=Packet.bytesToHexString(buf,off+6,6);
		EthAddress dst_addr=new EthAddress(buf,off);
		EthAddress src_addr=new EthAddress(buf,off+6);
		int type=((buf[off+12]&0xff)<<8) | (buf[off+13]&0xff);
		byte[] data_buf=buf;
		int data_off=off+14;
		int data_len=len-14;
		EthPacket pkt=new EthPacket(src_addr,dst_addr,type,data_buf,data_off,data_len);
		return pkt;
	}

	
	@Override
	public String toString() {
		//return "src="+src_addr+", dst="+dst_addr+", proto="+type+", datalen="+getPayloadLength();
		//return "src="+src_addr+", dst="+dst_addr+", proto="+type+", datalen="+getPayloadLength()+", payload="+ByteUtils.asHex(getBytes());
		return "ETH "+src_addr+" > "+dst_addr+" proto="+type+" datalen="+getPayloadLength();
	}

}
