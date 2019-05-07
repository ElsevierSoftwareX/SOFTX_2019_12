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


import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.util.IpAddressUtils;


/** Internet Protocol version 6 (IPv6) address.
 * <p>
 * The host-id part of the address (the suffix) is not required to be all zeros; non-zero suffix is simply ignored.
 */
public class Ip6Address implements IpAddress {

	/** Unspecified address  */
	public static final Ip6Address ADDR_UNSPECIFIED=new Ip6Address("::0");

	/** All hosts on local interface  */
	public static final Ip6Address ADDR_ALL_HOSTS_INTERFACE_MULTICAST=new Ip6Address("ff01::1");

	/** All hosts on the local network segment  */
	public static final Ip6Address ADDR_ALL_HOSTS_LINK_MULTICAST=new Ip6Address("ff02::1");

	/** All routers on the local network segment  */
	public static final Ip6Address ADDR_ALL_ROUTERS_LINK_MULTICAST=new Ip6Address("ff02::2");

	/** Multicast DNS  */
	public static final Ip6Address ADDR_MDNS_MULTICAST=new Ip6Address("ff02::fb");
	
	/** The IP address */
	byte[] addr=null;	
	
	/** The string IP address (cached) */
	String str_addr=null;
	
	
	/** Creates a new address.
	 * @param iaddr address */
	public Ip6Address(InetAddress iaddr) {
		this.addr=iaddr.getAddress();
	}
	
	/** Creates a new address.
	 * @param str_addr the string address */
	public Ip6Address(String str_addr) {
		this.addr=IpAddressUtils.stringIp6AddressToBytes(str_addr);
		this.str_addr=str_addr;
	}
	
	/** Creates a new address.
	 * @param buf byte array containing the address */
	public Ip6Address(byte[] buf) {
		this.addr=new byte[16];
		System.arraycopy(buf,0,this.addr,0,16);
	}
	
	/** Creates a new address.
	 * @param buf byte array containing the address
	 * @param off the offset within the buffer */
	public Ip6Address(byte[] buf, int off) {
		this.addr=new byte[16];
		System.arraycopy(buf,off,this.addr,0,16);
	}
	
	/*protected Ip6Address(Ip6Address ip_addr) {
		this.str_addr=ip_addr.str_addr;
		this.addr=ip_addr.addr;
	}*/
	
	@Override
	public InetAddress toInetAddress() {
		try {
			return Inet6Address.getByAddress(addr);
		}
		catch (UnknownHostException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	@Override
	public boolean equals(Object o) {
		Ip6Address ip_addr=null;
		if (o instanceof Ip6Address) ip_addr=(Ip6Address)o;
		else
			if (o instanceof String) ip_addr=new Ip6Address((String)o);
			else
				if (o instanceof byte[]) ip_addr=new Ip6Address((byte[])o);
				else
					return false;
		return Arrays.equals(addr,ip_addr.addr);
	}
	
	@Override
	public int hashCode() {
		return Arrays.hashCode(getBytes());
	}

	
	@Override
	public String toString() {
		if (str_addr==null) str_addr=IpAddressUtils.bytesToStringIp6Address(addr);
		return str_addr;
	}
	
	@Override
	public byte[] getBytes() {
		return addr;
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		System.arraycopy(addr,0,buf,off,16);
		return 16;
	}

	@Override
	public boolean isMulticast() {
		return Ip6Prefix.PREFIX_MULTICAST.contains(this);
	}

	/*@Override
	public int version() {
		return 6;
	}*/
	
	@Override
	public int length() {
		return 16;
	}

}
