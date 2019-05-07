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


/** IPv6 Type 0 Routing Header (&lt;draft-previdi-6man-segment-routing-header-07&gt;).
 */
public class Type0RoutingHeader extends RoutingHeader {
	
	
	/** Creates a new Type 0 Routing header.
	 * @param eh the header */
	public Type0RoutingHeader(ExtensionHeader eh) {
		super(eh);
	}

	
	/** Creates a new Type 0 Routing header.
	 * @param segment_list the segment list, encoded in the reverse order starting from the last segment of the path.
	 * I.e., the first element of the list contains the last segment of the path while the last segment of the list
	 * contains the first segment of the path */
	public Type0RoutingHeader(Ip6Address[] segment_list) {
		super(TYPE_RH0,segment_list.length-1,new byte[8+16*segment_list.length]);
		for (int i=0; i<segment_list.length; i++) segment_list[i].getBytes(buf,off+8+i*16);
		buf[off+4]=0x00; // reserved
		buf[off+5]=0x00; // reserved
		buf[off+6]=0x00; // reserved
		buf[off+7]=0x00; // reserved
	}

	
	/** Gets the Segment List.
	 * @return the segment list, encoded in the reverse order starting from the last segment of the path.
	 * I.e., the first element of the list contains the last segment of the path while the last segment of the list
	 * contains the first segment of the path */
	public Ip6Address[] getSegmentList() {
		Ip6Address[] segment_list=new Ip6Address[(len-8)/16];
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

}
