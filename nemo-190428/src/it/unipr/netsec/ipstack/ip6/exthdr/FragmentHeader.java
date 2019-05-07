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


import org.zoolu.util.ByteUtils;


/** IPv6 Fragment Header.
 */
public class FragmentHeader extends ExtensionHeader {
	
	/** Source Routing (RH0) */
	public static final int TYPE_RH0=0;
	
	/** Segment Routing (SRH) */
	public static final int TYPE_SRH=4;
	
	/** Routing type */
	//int routing_type;

	/** Segment left. The number of segments remaining */
	//int segment_left;


	
	/** Creates a new Fragment header.
	 * @param eh the header */
	public FragmentHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new Fragment header.
	 * @param buf buffer containing the header */
	public FragmentHeader(byte[] buf) {
		super(FRAGMENT_HDR,buf);
	}

	
	/** Creates a new Fragment header.
	 * @param buf buffer containing the header
	 * @param off offset within the buffer */
	public FragmentHeader(byte[] buf, int off) {
		super(FRAGMENT_HDR,buf,off,8);
	}

	
	/** Creates a new Fragment header.
	 * @param id 32-bit fragment identification value
	 * @param fragment_offset 13-bit offset, in 8-octet units, of the data relative to the start of the Fragmentable Part of the original packet
	 * @param more_fragments MF flag: true = more fragments, false = last fragment */
	public FragmentHeader(long id, int fragment_offset, boolean more_fragments) {
		super(FRAGMENT_HDR,new byte[8]);
		buf[0]=0;
		buf[1]=0;
		fragment_offset=(fragment_offset&0x1fff)<<3;
		buf[2]=(byte)(fragment_offset>>8);
		buf[3]=(byte)((fragment_offset&0xff)|(more_fragments?0x1:0x0));
		ByteUtils.intToFourBytes(id,buf,4);
	}

	
	/** Gets the fragment identifier.
	 * @return the fragment identification value */
	public long getId() {
		return ByteUtils.fourBytesToInt(buf,off+4);
	}

	
	/** Gets the fragment offset.
	 * @return the fragment offset in 8-octet units, of the data relative to the start of the Fragmentable Part of the original packet */
	public long getOffset() {
		return ByteUtils.twoBytesToInt(buf,off+2)>>3;
	}
	
	
	/** Gets the more fragment (MF) flag.
	 * @return true = more fragments, false = last fragment */
	public boolean hasMoreFragments() {
		return (buf[off+3]&0x1)==1;
	}
	
	
	/** Parses the given byte array for a Fragment Header.
	 * @param buf the buffer containing the Fragment Header
	 * @param off the offset within the buffer
	 * @param maxlen maximum number of bytes that can be processed
	 * @return the Fragment Header */
	public static FragmentHeader parseFragmentHeader(byte[] buf, int off, int maxlen) {
		if (maxlen<8) throw new RuntimeException("Malformed Header: too short");
		// else
		return new FragmentHeader(buf,off);
	}

	
	/** Parses the given byte array for a Routing Header.
	 * @param buf the buffer containing the Routing Header
	 * @param off the offset within the buffer
	 * @param maxlen maximum number of bytes that can be processed
	 * @return the IP packet */
	/*public static RoutingHeader parseRoutingHeader(byte[] buf, int off, int maxlen) {
		int routing_type=buf[off+2];
		if (routing_type==RoutingHeader.TYPE_SRH) {
			SegmentRoutingHeader srh=SegmentRoutingHeader.parseSegmentRoutingHeader(buf,off,maxlen);
			return srh;
		}
		// else
		throw new RuntimeException("Unsupported IPv6 Routing Header Type "+routing_type);
	}*/
}
