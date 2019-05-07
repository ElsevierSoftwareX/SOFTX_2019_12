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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;

import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.net.Address;


/** A transport address formed by an IP address and a port number.
 */
public class SocketAddress implements Address {

	/** IP address */
	IpAddress ipaddr;

	/** Port number */
	int port;

  
	/** Creates a transport address. */
	private SocketAddress() {
	}

	/** Creates a transport address.
	 * @param ipaddr IP address
	 * @param port port number */
	public SocketAddress(IpAddress ipaddr, int port) {
		init(ipaddr,port);
	}

	/** Creates a transport address.
	 * @param inetaddr IP address
	 * @param port port number */
	public SocketAddress(InetAddress inetaddr, int port) {
		IpAddress ipaddr;
		if (inetaddr instanceof Inet4Address) ipaddr=new Ip4Address(inetaddr);
		else if (inetaddr instanceof Inet6Address) ipaddr=new Ip6Address(inetaddr);
		else throw new RuntimeException("Unsupported socket address type: "+inetaddr);
		init(ipaddr,port);
	}

	/** Creates a transport address.
	 * @param soaddr string representing a socket address */
	public SocketAddress(String soaddr) {
		soaddr=soaddr.trim();
		if (soaddr.charAt(0)=='[') {
			// IPv6 address
			int end=soaddr.indexOf(']');
			if (end<0) throw new RuntimeException("Malformed IPv6 address: "+soaddr);
			// else
			Ip6Address ipaddr=new Ip6Address(soaddr.substring(1,end));
			int colon=soaddr.indexOf(':',end+1);
			if (colon<0) throw new RuntimeException("Malformed socket address: missing port number: "+soaddr);
			int port=Integer.parseInt(soaddr.substring(colon+1));
			init(ipaddr,port);
		}
		else {
			// IPv4 address
			int colon=soaddr.indexOf(':');
			if (colon<0) throw new RuntimeException("Malformed socket address: missing port number: "+soaddr);
			Ip4Address ipaddr=new Ip4Address(soaddr.substring(0,colon));
			port=Integer.parseInt(soaddr.substring(colon+1));
			init(ipaddr,port);
		}
	}

	/** Inits the transport address. */
	private void init(IpAddress ipaddr, int port) {
		if (ipaddr==null) throw new RuntimeException("Unvalid socket address: IP address cannot be null");
		if (port<0) throw new RuntimeException("Unvalid socket address: port number (\"+port+\") cannot be <0");
		this.ipaddr=ipaddr;
		this.port=port;
	}
  
	/** Gets the IP address.
	 * @return the address */
	public IpAddress getIpAddress() {
		return ipaddr;
	}

	/** Gets the port.
	 * @return the port number */
	public int getPort() {
		return port;
	}

	@Override
	public Object clone() {
		SocketAddress soaddr=new SocketAddress();
		soaddr.init(ipaddr,port);
		return soaddr;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof SocketAddress)) return false;
		// else
		SocketAddress saddr=(SocketAddress)obj;
		if (port!=saddr.port) return false;
		// else
		if (!ipaddr.equals(saddr.ipaddr)) return false;
		// else
		return true;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(getBytes());
	}

	@Override
	public String toString() {
		return toString(ipaddr,port);
	}

	@Override
	public byte[] getBytes() {
		byte[] buf=new byte[ipaddr.length()+2];
		int len=ipaddr.getBytes(buf,0);
		ByteUtils.intToTwoBytes(port,buf,len);
		return buf;
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		int len=ipaddr.getBytes(buf,off);
		ByteUtils.intToTwoBytes(port,buf,off+len);
		return len+2;
	}

	/** Returns IP address + port length. */
	public int length() {
		return ipaddr.length()+2;
	}

	/** Gets a string representation of a pair of IP address and port number.
	 * @param ipaddr the IP address
	 * @param port the port number
	 * @return standard IPv4 or IPv6 socket address representation */
	public static String toString(IpAddress ipaddr, int port) {
		StringBuffer sb=new StringBuffer();
		if (ipaddr==null) sb.append("null");
		else {
			if (ipaddr instanceof Ip6Address) sb.append('[').append(ipaddr.toString()).append(']');
			else sb.append(ipaddr.toString());
		}
		sb.append(':').append(port);
		return sb.toString();
	}	
	
}
