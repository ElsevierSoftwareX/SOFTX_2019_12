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

package it.unipr.netsec.ipstack.net;



/** Generic packet with data payload.
  */
public abstract class DataPacket implements Packet {
	
	/** Whether using a direct reference to the data buffer passed to the constructor, or making a copy */
	public static boolean DIRECT_DATA=false;

	/** Source address */
	protected Address src_addr=null;

	/** Destination address */
	protected Address dst_addr=null;


	/** Payload buffer */
	protected byte[] data_buf=null;

	/** Payload offset within the buffer */
	protected int data_off=0;

	/** Payload length */
	protected int data_len=0;

	
	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param data_buf the buffer containing the packet data
	 * @param data_off the offset within the buffer
	 * @param data_len the data length */
	public DataPacket(Address src_addr, Address dst_addr, byte[] data_buf, int data_off, int data_len) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.data_len=data_len;
		if (DIRECT_DATA) {
			this.data_buf=data_buf;
			this.data_off=data_off;
		}
		else {
			this.data_off=0;
			if (data_len>0) {
				this.data_buf=new byte[data_len];
				System.arraycopy(data_buf,data_off,this.data_buf,0,data_len);
			}
		}
	}
	 
	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param data the packet data */
	public DataPacket(Address src_addr, Address dst_addr, byte[] data) {
		this(src_addr,dst_addr,data,0,data!=null?data.length:0);
	}
	
	/** Creates a new packet.
	 * @param pkt the packet */
	protected DataPacket(DataPacket pkt) {
		this(pkt.src_addr,pkt.dst_addr,pkt.data_buf,pkt.data_off,pkt.data_len);
	}
	 
	/** Sets the source address.
	 * @param src_addr the IP source address */
	public void setSourceAddress(Address src_addr) {
		this.src_addr=src_addr;
	}
	 
	@Override
	public Address getSourceAddress() {
		return src_addr;
	}

	/** Sets the destination address.
	 * @param dst_addr the IP destination address */
	public void setDestAddress(Address dst_addr) {
		this.dst_addr=dst_addr;
	}
	 
	@Override
	public Address getDestAddress() {
		return dst_addr;
	}
  
	/** Sets packet payload.
	 * It replaces the payload buffer and updates the payload offset (0) and length.
	 * @param data the packet payload */
	public void setPayload(byte[] data) {
		setPayload(data,0,data!=null?data.length:0);
	}

	/** Sets packet payload.
	  * It replaces the payload buffer and updates the payload offset and length.
	 * @param data_buf the buffer containing the packet payload
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public void setPayload(byte[] data_buf, int data_off, int data_len) {
		this.data_buf=data_buf;
		this.data_off=data_off;
		this.data_len=data_len;
	}
	 
	/** Sets payload length.
	 * @param len the payload length */
	public void setPayloadLength(int len) {
		this.data_len=len;
	}

	/** Gets the payload buffer.
	 * @return the buffer containing the packet payload */
	public byte[] getPayloadBuffer() {
		return data_buf;
	}

	
	/** Gets offset within the payload buffer.
	 * @return the offset within the buffer containing the packet payload */
	public int getPayloadOffset() {
		return data_off;
	}

	/** Gets the payload length.
	 * @return the length */
	public int getPayloadLength() {
		return data_len;
	}

	/** Gets the packet payload (copy).
	 * @return a new byte array containing the payload */
	public byte[] getPayload() {
		byte[] data=new byte[data_len];
		for (int i=0; i<data_len; i++) data[i]=data_buf[data_off+i];
		return data;
	}
	
	@Override
	public abstract int getPacketLength();

	
	@Override
	public abstract int getBytes(byte[] buf, int off);

	
	@Override
	public byte[] getBytes() {
		int len=getPacketLength();
		byte[] data=new byte[len];
		getBytes(data,0);
		return data;
	}

	@Override
	public Object clone() {
		try {
			DataPacket pkt=(DataPacket)super.clone();
			pkt.data_buf=new byte[data_len];
			pkt.data_off=0;
			System.arraycopy(data_buf,data_off,pkt.data_buf,0,data_len);
			return pkt;
		}
		catch (CloneNotSupportedException e) {
			return null;
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName()+" "+src_addr+" > "+dst_addr+" datalen="+getPayloadLength();
	}

}
