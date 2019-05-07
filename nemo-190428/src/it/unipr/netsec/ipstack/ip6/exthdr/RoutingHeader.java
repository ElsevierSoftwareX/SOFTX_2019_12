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



/** IPv6 Routing Header.
 */
public class RoutingHeader extends ExtensionHeader {
	
	/** Source Routing (RH0) */
	public static final int TYPE_RH0=0;
	
	/** Segment Routing (SRH) */
	public static final int TYPE_SRH=4;
	
	/** Routing type */
	//int routing_type;

	/** Segment left. The number of segments remaining */
	//int segment_left;


	
	/** Creates a new Routing header.
	 * @param eh the header */
	public RoutingHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new Routing header.
	 * @param buf buffer containing the header */
	public RoutingHeader(byte[] buf) {
		super(ROUTING_HDR,buf);
	}

	
	/** Creates a new Routing header.
	 * @param buf buffer containing the header
	 * @param off offset within the buffer
	 * @param len extension header length */
	public RoutingHeader(byte[] buf, int off, int len) {
		super(ROUTING_HDR,buf,off,len);
	}

	
	/** Creates a new Routing header.
	 * @param routing_type routing type
	 * @param segment_left segment left field
	 * @param buf buffer containing the header */
	public RoutingHeader(int routing_type, int segment_left, byte[] buf) {
		super(ROUTING_HDR,buf);
		buf[1]=(byte)(len/8-1);
		buf[2]=(byte)routing_type;
		buf[3]=(byte)segment_left;
	}

	
	/** Creates a new Routing header.
	 * @param routing_type routing type
	 * @param segment_left segment left field
	 * @param buf buffer containing the header
	 * @param off offset within the buffer
	 * @param len header length */
	public RoutingHeader(int routing_type, int segment_left, byte[] buf, int off, int len) {
		super(ROUTING_HDR,buf,off,len);
		buf[off+1]=(byte)(len/8-1);
		buf[off+2]=(byte)routing_type;
		buf[off+3]=(byte)segment_left;
	}

	
	/** Gets routing type.
	 * @return the routing type */
	public int getRoutingType() {
		return buf[off+2]&0xff;
	}

	
	/** Gets segment left.
	 * The index, in the Segment List, of the next segment to inspect.
	 * Segments Left is decremented at each segment and it is used as an index in the segment list.
	 * @return the number of segments remaining */
	public int getSegmentLeft() {
		return buf[off+3]&0xff;
	}

	
	/** Sets segment left.
	 * The index, in the Segment List, of the next segment to inspect.
	 * Segments Left is decremented at each segment and it is used as an index in the segment list.
	 * @param segment_left the number of segments remaining */
	public void setSegmentLeft(int segment_left) {
		buf[off+3]=(byte)segment_left;
	}
	
	
	/** Parses the given byte array for a Routing Header.
	 * @param buf the buffer containing the Routing Header
	 * @param off the offset within the buffer
	 * @param maxlen maximum number of bytes that can be processed
	 * @return the Routing Header */
	public static RoutingHeader parseRoutingHeader(byte[] buf, int off, int maxlen) {
		int len=8*(buf[off+1]+1);
		if (len>maxlen) throw new RuntimeException("Malformed Header: too long");
		// else
		return new RoutingHeader(buf,off,len);
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
