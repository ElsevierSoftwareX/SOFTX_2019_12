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
import it.unipr.netsec.ipstack.net.Address;


/** Link State Update packet.
 */
public class OspfLSUPacket extends OspfPacket {
    		
	/** Creates a new LSU packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param router_id router ID
	 * @param area_id area ID
	 * @param lsa array of LSAs */
	public OspfLSUPacket(Address src_addr, Address dst_addr, Ip4Address router_id, Ip4Address area_id, LSA[] lsa) {
		super(src_addr,dst_addr,OspfPacket.TYPE_LSU,router_id,area_id,lsaToBytes(lsa));
	}
	
	/** Creates a new LSU packet.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf the buffer containing the LSU packet
	 * @param off the offset within the buffer
	 * @param len the length of the LSU packet */
	public OspfLSUPacket(Address src_addr, Address dst_addr, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		if (type!=OspfPacket.TYPE_LSU) throw new RuntimeException("OSPF packet type missmatches ("+type+"): it is not LSU packet ("+OspfPacket.TYPE_LSU+")");
	}	
	
	/** Creates a new LSU packet.
	 * @param pkt the LSU packet */
	public OspfLSUPacket(OspfPacket pkt) {
		super(pkt);
		if (type!=OspfPacket.TYPE_LSU) throw new RuntimeException("OSPF packet type missmatches ("+type+"): it is not LSU packet ("+OspfPacket.TYPE_LSU+")");
	}	
		
	/** Gets the LSAs.
	 * @return the LSAs */
	public LSA[] getLSAs() {
		int len=(int)ByteUtils.fourBytesToInt(body,0);
		LSA[] lsa=new LSA[len];
		int off=4;
		for (int i=0; i<len; i++) {
			lsa[i]=new LSA(body,off);
			off+=lsa[i].getLength();
		}
		return lsa;
	}
	
	
	/** Converts an array of LSAs into the corresponding packet bytes, including the number of LSAs.
	 * @param lsa array of LSA
	 * @return the corresponding packet bytes.*/
	private static byte[] lsaToBytes(LSA[] lsa) {
		int len=0;
		for (LSA a : lsa) len+=a.getLength();
		byte[] data=new byte[len+4];
		ByteUtils.intToFourBytes(lsa.length,data,0);
		int off=4;
		for (LSA a : lsa) {
			a.getBytes(data,off);
			off+=a.getLength();
		}
		return data;
	}

}
