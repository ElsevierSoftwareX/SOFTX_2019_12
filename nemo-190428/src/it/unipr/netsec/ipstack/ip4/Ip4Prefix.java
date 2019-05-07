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

package it.unipr.netsec.ipstack.ip4;


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.util.IpAddressUtils;


/** Internet Protocol version 4 (IPv4) network prefix.
 * <p>
 * Only prefix bits can be non-zeros.
 */
public class Ip4Prefix implements IpPrefix {

	/** Address ANY "0.0.0.0/0" */
	public static final Ip4Prefix ANY=new Ip4Prefix("0.0.0.0/0");

	/** Multicast prefix  */
	public static final Ip4Prefix PREFIX_MULTICAST=new Ip4Prefix("224.0.0.0/4");

	
	/** IP address */
	Ip4Address ip_addr;
	
	/** Prefix length */
	int prefix_len;
	
	
	/** Creates a new prefix.
	 * @param addr_and_prefix the address and prefix */
	public Ip4Prefix(String addr_and_prefix) {
		this(new Ip4Address(addr_and_prefix.substring(0,addr_and_prefix.indexOf('/'))),Integer.parseInt(addr_and_prefix.substring(addr_and_prefix.indexOf('/')+1)));
	}
	
	/** Creates a new prefix.
	 * @param addr IP address
	 * @param prefix_len prefix length */
	public Ip4Prefix(String addr, int prefix_len) {
		this(new Ip4Address(addr),prefix_len);
	}
	
	/** Creates a new prefix.
	 * @param addr IP address
	 * @param prefix_len prefix length */
	/*public Ip4Prefix(byte[] addr, int prefix_len) {
		this(addr,0,prefix_len);
	}*/
	
	/** Creates a new prefix.
	 * @param buf buffer containing the IP address
	 * @param off offset within the buffer
	 * @param prefix_len prefix length */
	public Ip4Prefix(byte[] buf, int off, int prefix_len) {
		this(new Ip4Address(buf,off),prefix_len);
	}
	
	/** Creates a new prefix.
	 * @param ip_addr IP address
	 * @param prefix_len prefix length */
	public Ip4Prefix(Ip4Address ip_addr, int prefix_len) {
		this.ip_addr=ip_addr;
		this.prefix_len=prefix_len;
		byte[] addr=ip_addr.getBytes();
		byte[] mask=IpAddressUtils.prefixLengthToMask(prefix_len);
		for (int i=0; i<4; i++) if ((addr[i]&(mask[i]^0xff)&0xff)!=0) throw new RuntimeException("Invalid prefix address: "+ip_addr+"/"+prefix_len);
	}
	
	@Override
	public Ip4Address prefixAddress() {
		return ip_addr;
	}
		
	@Override
	public int prefixLength() {
		return prefix_len;
	}
	
	@Override
	public byte[] prefixMask() {
		return IpAddressUtils.prefixLengthToMask(prefix_len);
	}
	
	/** Gets the subnet's broadcast address.
	 * @return the address */
	public Ip4Address getSubnetBroadcastAddress() {
		byte[] mask=IpAddressUtils.prefixLengthToMask(prefix_len);
		byte[] addr=ByteUtils.copy(getBytes());
		for (int i=0; i<addr.length; i++) addr[i]|=mask[i]^0xff;
		return new Ip4Address(addr);
	}
	
	/** Whether a given address matches this prefix.
	 * @param addr the address
	 * @return <i>true</i> if the given address belongs to this prefix; <i>false</i> otherwise */
	@Override
	public boolean contains(Address addr) {
		if (addr instanceof Ip4Prefix) {
			Ip4Prefix target_ip_prefix=(Ip4Prefix)addr;
			if (target_ip_prefix.prefixLength()<prefixLength()) return false;
			// else
			addr=target_ip_prefix.prefixAddress();
		}
		if (!(addr instanceof Ip4Address)) return false;
		// else
		Ip4Address target_ip_addr=(Ip4Address)addr;
		byte[] prefix_mask=IpAddressUtils.prefixLengthToMask(prefix_len);
		byte[] prefix_addr=ip_addr.getBytes();
		byte[] target_addr=target_ip_addr.getBytes();
		for (int i=0; i<target_addr.length; i++) if ((target_addr[i]&prefix_mask[i])!=prefix_addr[i]) return false;
		// else
		return true;
	}
	
	@Override
	public boolean equals(Object o) {
		Ip4Prefix prefix=null;
		if (o instanceof Ip4Prefix) prefix=(Ip4Prefix)o;
		else
			if (o instanceof String) prefix=new Ip4Prefix((String)o);
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

}
