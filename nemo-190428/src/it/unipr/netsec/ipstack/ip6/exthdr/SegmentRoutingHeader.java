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

package it.unipr.netsec.ipstack.ip6.exthdr;


import it.unipr.netsec.ipstack.ip6.Ip6Address;


/** IPv6 Segment Routing Header (&lt;draft-previdi-6man-segment-routing-header-07&gt;).
 */
public class SegmentRoutingHeader extends RoutingHeader {
	
	/** Debug mode */
	//private static final boolean DEBUG=false;

	
	
	/** First segment. Offset in the SRH not including the first 8 octects
	 * and expressed in 16-octect units, pointing to the last element
	 * of the segment list which is the first segment of the segment routing path */
	//int first_segment;

	/** Flags (16 bits of flags) */
	//int flags=0;
	
	/** HMAC key ID */
	//int key_id=0;
	
	/** Segment List[n]: 128 bit IPv6 addresses representing the nth
      segment in the Segment List.  The Segment List is encoded starting
      from the last segment of the path.  I.e., the first element of the
      segment list (Segment List [0]) contains the last segment of the
      path while the last segment of the Segment List (Segment List[n])
      contains the first segment of the path.  The index contained in
      "Segments Left" identifies the current active segment */
	//Ip6Address[] segment_list=null;

	/** Policy List. Optional addresses representing specific nodes in
      the SR path */
	//Ip6Address[] policy_list=null;
	
	/** HMAC field. Optional */
	//byte[] hmac=null;
	

	
	/** Creates a new SR header. */
	/*public SegmentRoutingHeader() {
		super(TYPE_SRH);
	}*/

	
	/** Creates a new SR header.
	 * @param eh the header */
	public SegmentRoutingHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new SR header.
	 * @param segment_list the segment list, encoded in the reverse order starting from the last segment of the path.
	 * I.e., the first element of the list contains the last segment of the path while the last segment of the list
	 * contains the first segment of the path */
	public SegmentRoutingHeader(Ip6Address[] segment_list) {
		super(TYPE_SRH,segment_list.length-1,new byte[8+16*segment_list.length]);
		for (int i=0; i<segment_list.length; i++) segment_list[i].getBytes(buf,off+8+i*16);
		setFirstSegment(segment_list.length-1);
		buf[off+5]=0x00; // flags
		buf[off+6]=0x00; // flags
		buf[off+7]=0x00; // key id
	}

	
	/** Creates a new SR header.
	 * @param segment_list the segment list, encoded in the reverse order starting from the last segment of the path.
	 * I.e., the first element of the list contains the last segment of the path while the last segment of the list
	 * contains the first segment of the path
	 * @param policy_list the policy list
	 * @param key_id the H-MAC key identifier
	 * @param hmac the H-MAC */
	public SegmentRoutingHeader(Ip6Address[] segment_list, PolicyElement[] policy_list, int key_id, byte[] hmac) {
		super(TYPE_SRH,segment_list.length-1,new byte[headerLength(segment_list,policy_list,hmac)]);
		setFirstSegment(segment_list.length-1);
		buf[off+5]=0x00; // flags
		buf[off+6]=0x00; // flags
		buf[off+7]=(byte)(key_id); // key id		
		for (int i=0; i<segment_list.length; i++) segment_list[i].getBytes(buf,off+8+i*16);
		int index=off+8+16*segment_list.length;
		if (policy_list!=null) {
			for (int i=0; i<policy_list.length; i++) {
				PolicyElement pelem=policy_list[i];
				this.setPolicyType(i,pelem.getType());
				pelem.getAddress().getBytes(buf,index);
				index+=16;
			}
		}
		if (hmac!=null) {
			System.arraycopy(hmac,0,buf,index,hmac.length);
		}
	}

	
	/** Computes the header length based on the selected fields.
	 * @param segment_list segment list
	 * @param policy_list policy list
	 * @param hmac the H-MAC */
	private static int headerLength(Ip6Address[] segment_list, PolicyElement[] policy_list, byte[] hmac) {
		return 8+16*segment_list.length+16*(policy_list!=null?policy_list.length:0)+(hmac!=null?hmac.length:0);
	}

	
	/**Gets first segment.
	 * Offset in the SRH not including the first 8 octects and expressed in 16-octect units,
	 * pointing to the last element of the segment list which is the first segment of the segment routing path.
	 * @return the first segment */
	public int getFirstSegment() {
		return buf[off+4]&0xff;
	}

	
	/**Sets first segment.
	 * Offset in the SRH not including the first 8 octects and expressed in 16-octect units,
	 * pointing to the last element of the segment list which is the first segment of the segment routing path.
	 * @param first_segment the first segment to set */
	public void setFirstSegment(int first_segment) {
		buf[off+4]=(byte)first_segment;
	}

	
	/** Gets flags (16 bits of flags).
	 * @return the flags */
	/*public int getFlags() {
		return ((buf[off+5]&0xff)<<8) | (buf[off+6]&0xff);
	}*/


	/** Sets flags (16 bits of flags).
	 * @param flags the flags to set */
	/*public void setFlags(int flags) {
		buf[off+5]=(byte)((flags&0xff00)>>8);
		buf[off+6]=(byte)(flags&0xff00);
	}*/

	
	/** Gets the Clean-up (C) flag.
	 * @return the flag value */
	public boolean getCleanupFlag() {
		return (buf[off+5]&0x80)==0x80;
	}


	/** Sets the Clean-up (C) flag.
	 * @param value the flag value to set */
	public void setCleanupFlag(boolean value) {
		buf[off+5]=(byte)((buf[off+5]&0x7f)|(value?0x80:0x00));
	}

	
	/** Gets the Protected (P) flag.
	 * @return the flag value */
	public boolean getProtectedFlag() {
		return (buf[off+5]&0x40)==0x40;
	}


	/** Sets the Protected (P) flag.
	 * @param value the flag value to set */
	public void setProtectedFlag(boolean value) {
		buf[off+5]=(byte)((buf[off+5]&0xbf)|(value?0x40:0x00));
	}

	
	/** Gets the type of the k-th element of the policy list.
	 * @param k the index of the element of the policy list (0, 1, 2, or 3)
	 * @return the type */
	protected short getPolicyType(int k) {
		switch (k) {
			case 0 : return (short)((buf[off+5]&0x0e)>>1);
			case 1 : return (short)(((buf[off+5]&0x01)<<2) | ((buf[off+6]&0xc0)>>6));
			case 2 : return (short)((buf[off+6]&0x38)>>3);
			case 3 : return (short)(buf[off+6]&0x07);
			default : throw new RuntimeException("Invalid policy element index: "+k); 
		}
	}


	/** Sets the type of the k-th element of the policy list.
	 * @param k the index of the element of the policy list
	 * @param type the type */
	protected void setPolicyType(int k, short type) {
	    if (type<0 || type>3) throw new RuntimeException("Invalid policy element type: "+type);
		switch (k) {
		case 0 : buf[off+5]=(byte)((buf[off+5]&0xf1)|(type<<1)); break;
		case 1 : buf[off+5]=(byte)((buf[off+5]&0xfe)|((type&0x4)>>2)); buf[off+6]=(byte)((buf[off+6]&0x3f)|((type&0x3)<<6)); break;
		case 2 : buf[off+6]=(byte)((buf[off+6]&0xc7)|(type<<3)); break;
		case 3 : buf[off+6]=(byte)((buf[off+6]&0xf8)|(type)); break;
		default : throw new RuntimeException("Invalid policy element index: "+k); 
		}
	}


	/** Gets policy List.
	 * @return the policy list */
	public PolicyElement[] getPolicyList() {
		int len=getPolicyType(3)!=0? 4 : getPolicyType(2)!=0? 3 : getPolicyType(1)!=0? 2 : getPolicyType(0)!=0? 1 : 0;
		PolicyElement[] policy_list=new PolicyElement[len];
		for (int i=0; i<policy_list.length; i++) {
			policy_list[i]=getPolicyElementAt(i);
		}
		return policy_list;
	}

	
	/** Gets the k-th policy element (of the policy list).
	 * @param k the index of the element of the policy list (0, 1, 2, or 3)
	 * @return the policy element */
	public PolicyElement getPolicyElementAt(int k) {
		return new PolicyElement(getPolicyType(k),new Ip6Address(buf,off+8+16*getFirstSegment()+16+k*16));
	}


	/** Gets the H-MAC key id. 
	 * @return the key_id */
	public int getHmacKeyId() {
		return buf[off+7]&0xff;
	}


	/** Sets the H-MAC key id. 
	 * @param key_id the key_id to set */
	public void setHmacKeyId(int key_id) {
		buf[off+7]=(byte)key_id;
	}


	/** Gets the Segment List.
	 * @return the segment list, encoded in the reverse order starting from the last segment of the path.
	 * I.e., the first element of the list contains the last segment of the path while the last segment of the list
	 * contains the first segment of the path */
	public Ip6Address[] getSegmentList() {
		Ip6Address[] segment_list=new Ip6Address[getFirstSegment()+1];
		for (int i=0; i<segment_list.length; i++) {
			segment_list[i]=new Ip6Address(buf,off+8+i*16);
		}
		return segment_list;
	}

	
	/** Gets the segment at a given position.
	 * @param i the index of the segment
	 * @return the i-th segment */
	public Ip6Address getSegmentAt(int i) {
		return new Ip6Address(buf,off+8+16*i);
	}

	
	/** Gets H-MAC field.
	 * @return the H-MAC value */
	public byte[] getHMac() {
		return null;
	}

	
	/** Policy element. */
	public static class PolicyElement {
		
		/** Policy element Not present */
		public static final short NOT_PRESENT=0x0;

		/** Policy element SR Ingress */
		public static final short SR_INGRESS=0x1;

		/** Policy element SR Egress */
		public static final short SR_EGRESS=0x2;

		/** Policy element Original Source Address */
		public static final short SOURCE_ADDRESS=0x3;

		
		/** Policy element type */
		short type;
		
		/** Element address */
		Ip6Address addr;

		
		/** Creates a new PolicyElement.
		 * @param type the policy element type (0=Not present, 1=SR Ingress, 2=SR Egress, or 3=Original Source Address)
		 * @param addr the element address */
		public PolicyElement(short type, Ip6Address addr) {
		    if (type<=0 || type>3) throw new RuntimeException("Invalid policy element type: "+type);
			this.type=type;
			this.addr=addr;
		}
		
		@Override
		public String toString() {
			return addr.toString();
		}
		
		/** Gets the element type. 
		 * @return the policy element type (0=Not present, 1=SR Ingress, 2=SR Egress, or 3=Original Source Address) */
		public short getType() {
			return type;
		}

		/** Gets the element address. 
		 * @return the 128-bit address */
		public Ip6Address getAddress() {
			return addr;
		}
	}

}
