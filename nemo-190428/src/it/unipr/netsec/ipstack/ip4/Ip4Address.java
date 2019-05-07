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


import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import it.unipr.netsec.ipstack.util.IpAddressUtils;


/** Internet Protocol version 4 (IPv4) address.
 */
public class Ip4Address implements IpAddress {

	/** Any address */
	public static final Ip4Address ADDR_UNSPECIFIED=new Ip4Address("0.0.0.0");

	/** Broadcast address */
	public static final Ip4Address ADDR_BROADCAST=new Ip4Address("255.255.255.255");

	/** The All Hosts multicast group addresses all hosts on the same network segment */
	public static final Ip4Address  ADDR_ALL_HOSTS_MULTICAST=new Ip4Address("224.0.0.1");
	
	/** The All Routers multicast group addresses all routers on the same network segment */
	public static final Ip4Address  ADDR_ALL_ROUTERS_MULTICAST=new Ip4Address("224.0.0.2");

	/** Internet Group Management Protocol (IGMP) version 3 */
	public static final Ip4Address  ADDR_IGMP3_MULTICAST=new Ip4Address("224.0.0.22");

	/** Multicast DNS (mDNS) address */
	public static final Ip4Address ADDR_MDNS_MULTICAST=new Ip4Address("224.0.0.251");

		
	/** The IP address */
	byte[] addr=null;

	/** The string IP address (cached) */
	String str_addr=null;
	
	
	/** Creates a new address.
	 * @param iaddr address */
	public Ip4Address(InetAddress iaddr) {
		this.addr=iaddr.getAddress();
	}
	
	/** Creates a new address.
	 * @param str_addr the string address */
	public Ip4Address(String str_addr) {
		this.addr=IpAddressUtils.stringIp4AddressToBytes(str_addr);
		this.str_addr=str_addr;
	}
	
	/** Creates a new address.
	 * @param addr the address */
	public Ip4Address(byte[] addr) {
		this.addr=new byte[4];
		System.arraycopy(addr,0,this.addr,0,4);
	}
	
	/** Creates a new address.
	 * @param buf byte array containing the address
	 * @param off the offset within the buffer */
	public Ip4Address(byte[] buf, int off) {
		addr=new byte[4];
		System.arraycopy(buf,off,addr,0,4);
	}
	
	@Override
	public InetAddress toInetAddress() {
		try {
			return Inet4Address.getByAddress(addr);
		}
		catch (UnknownHostException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	/*protected Ip4Address(Ip4Address ip_addr) {
		this.str_addr=ip_addr.str_addr;
		this.addr=ip_addr.addr;
	}*/
	
	@Override
	public boolean equals(Object o) {
		Ip4Address ip_addr=null;
		if (o instanceof Ip4Address) ip_addr=(Ip4Address)o;
		else
			if (o instanceof String) ip_addr=new Ip4Address((String)o);
			else
				if (o instanceof byte[]) ip_addr=new Ip4Address((byte[])o);
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
		if (str_addr==null) str_addr=IpAddressUtils.bytesToStringIp4Address(addr);
		return str_addr;
	}
	
	@Override
	public byte[] getBytes() {
		return addr;
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		System.arraycopy(addr,0,buf,off,4);
		return 4;
	}
	
	@Override
	public boolean isMulticast() {
		return ADDR_BROADCAST.equals(this) || Ip4Prefix.PREFIX_MULTICAST.contains(this);
	}

	/*@Override
	public int version() {
		return 4;
	}*/
	
	@Override
	public int length() {
		return 4;
	}

}
