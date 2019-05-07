package it.unipr.netsec.nemo.examples.p1;


import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;


/** Packet of protocol P1.
 * <p>
 * A P1 packet contains three string fields:
 * <ul>
 * <li>source address;</li>
 * <li>destination address;</li>
 * <li>payload.</li>
 * </ul> 
 * These fields are concatenated separated by a space, i.e.: packet := src + ' ' + dst + ' ' + payload.
 */
public class P1Packet implements Packet {
	
	P1Address src_addr;
	P1Address dst_addr;	
	String payload;
	
	/** Creates a new packet.
	 * @param src_addr source address
	 * @param dst_addr destination address
	 * @param payload the payload data */
	public P1Packet(P1Address src_addr, P1Address dst_addr, String payload) {
		this.src_addr=src_addr;
		this.dst_addr=dst_addr;
		this.payload=payload;
	}
	
	/** Creates a new packet.
	 * @param buf the buffer containing the packet
	 * @param off the offset within the buffer
	 * @param len packet length */
	public P1Packet(byte[] buf, int off, int len) {
		String[] a=new String(buf,off,len).split(" ");
		if (a.length!=3) throw new RuntimeException("Invalid number of fields: "+a.length);
		src_addr=new P1Address(a[0]);
		dst_addr=new P1Address(a[1]);
		payload=a[2];
	}
	
	@Override
	public Object clone() {
		return new P1Packet(src_addr,dst_addr,payload);
	}

	@Override
	public Address getSourceAddress() {
		return src_addr;
	}

	@Override
	public Address getDestAddress() {
		return dst_addr;
	}

	@Override
	public int getPacketLength() {
		return getBytes().length;
	}
	
	@Override
	public byte[] getBytes() {
		String str=""+src_addr+' '+dst_addr+' '+payload;
		return str.getBytes();
	}
		
	@Override
	public int getBytes(byte[] buf, int off) {
		byte[] data=getBytes();
		System.arraycopy(data,0,buf,off,data.length);
		return data.length;
	}
		
	@Override
	public String toString() {
		return "P1 "+src_addr+" > "+dst_addr+" payload="+payload;
	}

}
