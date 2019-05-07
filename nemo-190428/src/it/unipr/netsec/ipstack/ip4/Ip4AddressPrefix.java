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


import it.unipr.netsec.ipstack.util.IpAddressUtils;


/** Internet Protocol version 4 (IPv4) address with prefix length.
 * <p>
 * It extends class {@link Ip4Address} by simply adding prefix length information.
 */
public class Ip4AddressPrefix extends Ip4Address implements IpAddressPrefix {

	/** Prefix length */
	int prefix_len;
	
	
	/** Creates a new address.
	 * @param addr_and_prefix the address and prefix */
	public Ip4AddressPrefix(String addr_and_prefix) {
		super(addr_and_prefix.substring(0,addr_and_prefix.indexOf('/')));
		prefix_len=Integer.parseInt(addr_and_prefix.substring(addr_and_prefix.indexOf('/')+1));
	}

	/** Creates a new address.
	 * @param addr IP address
	 * @param prefix_len prefix length */
	public Ip4AddressPrefix(String addr, int prefix_len) {
		super(addr);
		this.prefix_len=prefix_len;
	}
	
	/** Creates a new address.
	 * @param addr IP address
	 * @param prefix_len prefix length */
	/*public Ip4AddressPrefix(byte[] addr, int prefix_len) {
		this(addr,0,prefix_len);
	}*/
	
	/** Creates a new address.
	 * @param buf buffer containing the IP address
	 * @param off offset within the buffer
	 * @param prefix_len prefix length */
	public Ip4AddressPrefix(byte[] buf, int off, int prefix_len) {
		super(buf,off);
		this.prefix_len=prefix_len;
	}
	
	/** Creates a new address.
	 * @param ip_addr IP address
	 * @param prefix_len prefix length */
	public Ip4AddressPrefix(Ip4Address ip_addr, int prefix_len) {
		super(ip_addr.addr);
		this.prefix_len=prefix_len;
	}
	
	@Override
	public int getPrefixLength() {
		return prefix_len;
	}
	
	@Override
	public Ip4Prefix getPrefix() {
		byte[] prefix_mask=IpAddressUtils.prefixLengthToMask(prefix_len);
		byte[] prefix_addr=new byte[prefix_mask.length];
		for (int i=0; i<prefix_addr.length; i++) prefix_addr[i]=(byte)(addr[i]&prefix_mask[i]);
		return new Ip4Prefix(prefix_addr,0,prefix_len);
	}
	
	@Override
	public String toStringWithPrefixLength() {
		return super.toString()+"/"+prefix_len;
	}

}
