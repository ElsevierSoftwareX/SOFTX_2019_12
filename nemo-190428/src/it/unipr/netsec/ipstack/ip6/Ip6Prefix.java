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

package it.unipr.netsec.ipstack.ip6;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.net.Address;


/** Internet Protocol version 6 (IPv6) network prefix.
 * <p>
 * Only prefix bits can be non-zeros.
 */
public class Ip6Prefix implements IpPrefix {
	
	/** Address ANY "::/0" */
	public static final Ip6Prefix ANY=new Ip6Prefix("::/0");

	/** Multicast prefix  */
	public static final Ip6Prefix PREFIX_MULTICAST=new Ip6Prefix("ff00::/8");

	/** IP address */
	Ip6Address ip_addr;
	
	/** Prefix length */
	int prefix_len;

	/** Prefix mask */
	byte[] prefix_mask=null;

	
	/** Creates a new prefix.
	 * @param addr_and_prefix the address and prefix */
	public Ip6Prefix(String addr_and_prefix) {
		this(new Ip6Address(addr_and_prefix.substring(0,addr_and_prefix.indexOf('/'))),Integer.parseInt(addr_and_prefix.substring(addr_and_prefix.indexOf('/')+1)));
	}
	
	/** Creates a new prefix.
	 * @param addr IP address
	 * @param prefix_len prefix length */
	public Ip6Prefix(String addr, int prefix_len) {
		this(new Ip6Address(addr),prefix_len);
	}
	
	/** Creates a new prefix.
	 * @param addr IP address
	 * @param prefix_len prefix length */
	/*public Ip6Prefix(byte[] addr, int prefix_len) {
		this(addr,0,prefix_len);
	}*/
	
	
	/** Creates a new prefix.
	 * @param buf buffer containing the IP address
	 * @param off offset within the buffer
	 * @param prefix_len prefix length */
	public Ip6Prefix(byte[] buf, int off, int prefix_len) {
		this(new Ip6Address(buf,off),prefix_len);
	}
	
	/** Creates a new prefix.
	 * @param ip_addr IP address
	 * @param prefix_len prefix length */
	public Ip6Prefix(Ip6Address ip_addr, int prefix_len) {
		this.ip_addr=ip_addr;
		this.prefix_len=prefix_len;
		byte[] addr=ip_addr.getBytes();
		byte[] mask=prefixMask(prefix_len);
		for (int i=0; i<16; i++) if ((addr[i]&(mask[i]^0xff)&0xff)!=0) throw new RuntimeException("Invalid prefix address: "+ip_addr+"/"+prefix_len);
	}
		
	@Override
	public Ip6Address prefixAddress() {
		return ip_addr;
	}
		
	@Override
	public int prefixLength() {
		return prefix_len;
	}
	
	@Override
	public byte[] prefixMask() {
		return prefixMask(prefix_len);
	}
	
	/** Gets the network broadcast address */
	/*public Ip6Address getNetworkBroadcastAddress() {
		byte[] mask=prefixMask();
		for (int i=0; i<mask.length; i++) mask[i]^=0xff;
		byte[] addr=ByteUtils.copyOf(getBytes());
		for (int i=0; i<addr.length; i++) addr[i]|=mask[i];
		return new Ip6Address(addr);
	}*/
	
	/** Whether a given address matches this prefix.
	 * @param addr the address
	 * @return <i>true</i> if the given address belongs to this prefix; <i>false</i> otherwise */
	@Override
	public boolean contains(Address addr) {
		if (addr instanceof Ip6Prefix) {
			Ip6Prefix target_ip_prefix=(Ip6Prefix)addr;
			if (target_ip_prefix.prefixLength()<prefixLength()) return false;
			// else
			addr=target_ip_prefix.prefixAddress();
		}
		if (!(addr instanceof Ip6Address)) return false;
		// else
		Ip6Address target_ip_addr=(Ip6Address)addr;		
		byte[] prefix_mask=prefixMask(prefix_len);
		byte[] prefix_addr=ip_addr.getBytes();
		byte[] target_addr=target_ip_addr.getBytes();
		for (int i=0; i<target_addr.length; i++) if ((target_addr[i]&prefix_mask[i])!=prefix_addr[i]) return false;
		// else
		return true;
	}
	
	@Override
	public boolean equals(Object o) {
		Ip6Prefix prefix=null;
		if (o instanceof Ip6Prefix) prefix=(Ip6Prefix)o;
		else
			if (o instanceof String) prefix=new Ip6Prefix((String)o);
			else
				return false;
		return this.contains(prefix.prefixAddress()) && prefix.contains(this.prefixAddress());
	}
	
	@Override
	public String toString() {
		return ip_addr.toString()+"/"+prefix_len;
	}

	@Override
	public byte[] getBytes() {
		return ip_addr.getBytes();
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		return ip_addr.getBytes(buf,off);
	}
	
	/** All possible prefix masks */
	private static byte[][] PREFIX_MASKS;
	
	/** Gets a prefix mask.
	 * @param len the prefix len
	 * @return the prefix mask */
	public static byte[] prefixMask(int len) {
		if (PREFIX_MASKS==null) PREFIX_MASKS=new byte[129][];
		if (PREFIX_MASKS[len]==null) PREFIX_MASKS[len]=newPrefixMask(len);
		return PREFIX_MASKS[len];
	}
	
	/** Creates a mask for a given prefix length.
	 * @param len the prefix length
	 * @return the prefix mask */
	private static byte[] newPrefixMask(int len) {
		byte[] mask=new byte[16];
		for (int i=0; i<16; i++) {
			int remainder=len-i*8;
			if (remainder>=8) mask[i]=(byte)0xff;
			else 
			if (remainder<=0) mask[i]=(byte)0x00;
			else
			switch (remainder) {
				case 7 : mask[i]=(byte)0xfe; break;
				case 6 : mask[i]=(byte)0xfc; break;
				case 5 : mask[i]=(byte)0xf8; break;
				case 4 : mask[i]=(byte)0xf0; break;
				case 3 : mask[i]=(byte)0xe0; break;
				case 2 : mask[i]=(byte)0xc0; break;
				case 1 : mask[i]=(byte)0x80; break;			
			}
		}
		return mask;
	}
	
}
