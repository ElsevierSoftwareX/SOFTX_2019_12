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

package it.unipr.netsec.ipstack.util;


import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Arrays;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpAddressPrefix;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;


/** Collection of static methods for managing IP addresses.
 */
public class IpAddressUtils {


	// ************************* IPv4 ADDRESSES *************************

	/** Converts a dot-decimal string representation of IPv4 address to an array of four bytes.
	 * @param addr the string address
	 * @return a 4-byte array containing the address */
	public static byte[] stringIp4AddressToBytes(String addr) {
		byte[] buf=new byte[4];
		stringIp4AddressToBytes(addr,buf,0);
		return buf;
	}
	
	/** Converts a dot-decimal string representation of IPv4 address to an array of four bytes.
	 * @param addr the string address
	 * @param buf the buffer where the 4-byte address is going to be written
	 * @param off the offset within the buffer */
	public static void stringIp4AddressToBytes(String addr, byte[] buf, int off) {
		try {
			String[] ss=addr.split("\\x2e"); // 0x2e = '.'
			if (ss.length!=4) throw new RuntimeException("wrong length ("+ss.length+")");
			for (int i=0; i<4; i++) {
				int val=Integer.valueOf(ss[i]);
				if ((val>>8)!=0) throw new RuntimeException("value exceeds 255");
				buf[off++]=(byte)(val&0xff);
			}			
		}
		catch (Exception e) {
			throw new RuntimeException("Wrong IPv4 address ('"+addr+"'): "+e.toString());
		}
	}
	/*public static void stringAddressToBytes(String addr, byte[] buf, int off) {
		int begin=0;
		int end;
		for (int i=0; i<3; i++) {
			end=addr.indexOf('.',begin);
			buf[off+i]=(byte)Integer.parseInt(addr.substring(begin,end));
			begin=end+1;
		}
		buf[off+3]=(byte)Integer.parseInt(addr.substring(begin));
	}*/
	
	/** Gets the dot-decimal string representation of an IPv4 address.
	 * @param addr the buffer containing the IPv4 address
	 * @return the IPv4 address */
	public static String bytesToStringIp4Address(byte[] addr) {
		return bytesToStringIp4Address(addr,0);
	}
		
	/** Gets the dot-decimal string representation of an IPv4 address.
	 * @param buf the buffer containing the IPv4 address
	 * @param off the offset within the buffer
	 * @return the IPv4 address */
	public static String bytesToStringIp4Address(byte[] buf, int off) {
		StringBuffer sb=new StringBuffer();
		for (int i=0; i<4; i++) {
			int n=buf[off+i]&0xff;
			sb.append(n);
			if (i<3) sb.append('.');
		}
		return sb.toString();
	}
	/*public static String bytesToStringAddress(byte[] buf, int off) {
		return Integer.toString(BinTools.uByte(buf[off++]))+"."+Integer.toString(BinTools.uByte(buf[off++]))+"."+Integer.toString(BinTools.uByte(buf[off++]))+"."+Integer.toString(BinTools.uByte(buf[off]));
	}*/
	
	/** All possible prefix masks */
	private static byte[][] PREFIX_MASKS;

	/** Gets prefix mask for a given prefix len.
	 * @param len the prefix len
	 * @return the prefix mask */
	public static byte[] prefixLengthToMask(int len) {
		if (PREFIX_MASKS==null) PREFIX_MASKS=new byte[33][];
		if (PREFIX_MASKS[len]==null) {
			byte[] mask=new byte[4];
			for (int i=0; i<4; i++) {
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
			return PREFIX_MASKS[len]=mask;
		}
		else {
			return PREFIX_MASKS[len];			
		}
	}
	
	/** Gets the prefix length from a network mask
	 * @param mask the network mask
	 * @return the prefix length */
	public static int maskToPrefixLength(byte[] mask) {
		return maskToPrefixLength(mask,0);
	}
	
	/** Gets the prefix length from a network mask
	 * @param buf the buffer containing the network mask
	 * @param off the offset within the buffer
	 * @return the prefix length */
	public static int maskToPrefixLength(byte[] buf, int off) {
		int len=0;
		int i=0;
		for (; i<4 && buf[off+i]==(byte)0xff; i++) len+=8;
		if (i<4) {
			switch (buf[off+i]) {
				case (byte)0xfe : len+=7; break;
				case (byte)0xfc : len+=6; break;
				case (byte)0xf8 : len+=5; break;
				case (byte)0xf0 : len+=4; break;
				case (byte)0xe0 : len+=3; break;
				case (byte)0xc0 : len+=2; break;
				case (byte)0x80 : len+=1; break;
				case (byte)0x00 : break;
				default : throw new RuntimeException("Invalid network mask '"+bytesToStringIp4Address(buf,off)+"'");
			}
			for (int j=i+1; j<4; j++) {
				if (buf[off+j]!=0) throw new RuntimeException("Invalid network mask '"+bytesToStringIp4Address(buf,off)+"'");
			}
		}		
		return len;
	}

	/** Converts a {@link java.net.InetAddress} to a {@link it.unipr.netsec.ipstack.ip4.IpAddress}.
	 * @param inet_addr the InetAddress to be converted
	 * @return the IpAddress */
	public static IpAddress toIpAddress(InetAddress inet_addr) {
		return inet_addr instanceof Inet4Address? new Ip4Address(inet_addr) : new Ip6Address(inet_addr);
	}
	
		
	// ************************* IPv6 ADDRESSES *************************
	
	/** Converts a string representation of an IPv6 address to an array of bytes.
	 * @param addr the string address
	 * @return a 16-byte array containing the address */
	public static byte[] stringIp6AddressToBytes(String addr) {
		byte[] buf=new byte[16];
		stringIp6AddressToBytes(addr,buf,0);
		return buf;
	}
	
	/** Converts a string representation of an IPv6 address to an array of bytes.
	 * @param addr the string address
	 * @param buf the buffer where the 16-byte address is going to be written
	 * @param off the offset within the buffer */
	public static void stringIp6AddressToBytes(String addr, byte[] buf, int off) {
		try {
			int split_index=addr.indexOf("::");
			if (split_index>=0) {
				String[] leading_ss=addr.substring(0,split_index).split(":");
				if (leading_ss.length==1 && leading_ss[0].length()==0) leading_ss=new String[]{};
				String[] tailing_ss=addr.substring(split_index+2).split(":");
				if (tailing_ss.length==1 && tailing_ss[0].length()==0) tailing_ss=new String[]{};
				for (int i=0; i<leading_ss.length; i++) {
					//SystemUtils.log(LoggerLevel.DEBUG,"Ip6Address: stringToBytes(): leading_ss["+i+"]: "+leading_ss[i]);
					int val=Integer.valueOf(leading_ss[i],16);
					buf[off++]=(byte)((val&0xff00)>>8);
					buf[off++]=(byte)(val&0xff);
				}
				int zero_len=2*(8-leading_ss.length-tailing_ss.length);
				Arrays.fill(buf,off,off+zero_len,(byte)0);
				off+=zero_len;
				for (int i=0; i<tailing_ss.length; i++) {
					//SystemUtils.log(LoggerLevel.DEBUG,"Ip6Address: stringToBytes(): tailing_ss["+(leading_ss.length+zero_len/2+i)+"]: "+tailing_ss[i]);
					int val=Integer.valueOf(tailing_ss[i],16);
					buf[off++]=(byte)((val&0xff00)>>8);
					buf[off++]=(byte)(val&0xff);
				}
			}
			else {
				String[] ss=addr.split(":");
				if (ss.length!=8) new RuntimeException("wrong length");
				for (int i=0; i<8; i++) {
					//SystemUtils.log(LoggerLevel.DEBUG,"Ip6Address: stringToBytes(): addr["+i+"]: "+ss[i]);
					int val=Integer.valueOf(ss[i],16);
					buf[off++]=(byte)((val&0xff00)>>8);
					buf[off++]=(byte)(val&0xff);
				}
			}
		}
		catch (Exception e) {
			throw new RuntimeException("Wrong IPv6 address ('"+addr+"'): "+e.toString());
		}
	}
	
	/** Gets a string representation of an IPv6 address.
	 * @param addr the buffer containing the IPv6 address
	 * @return the IPv6 address */
	public static String bytesToStringIp6Address(byte[] addr) {
		return bytesToStringIp6Address(addr,0);
	}
		
	/** Gets a string representation of an IPv6 address.
	 * @param buf the buffer containing the IPv6 address
	 * @param off the offset within the buffer
	 * @return the IPv6 address */
	public static String bytesToStringIp6Address(byte[] buf, int off) {
		int[] addr=new int[8];
		for (int i=0; i<8; i++) {
			addr[i]=(buf[off++]&0xff)<<8;
			addr[i]|=buf[off++]&0xff;
		}
		// find the longest sequence of zeros
		int zero_max_count=0;
		int zero_max_index=0;
		int zero_index=0;
		int zero_count=0;
		boolean zero_run=false;
		for (int i=0; i<8; i++) {
			//SystemUtils.log(LoggerLevel.DEBUG,"Ip6Address: bytesToString(): addr["+i+"]: "+addr[i]);
			if (addr[i]==0) {
				if (zero_run) zero_count++;
				else {
					zero_run=true;
					zero_index=i;
					zero_count=1;
				}
			}
			else
			if (zero_run) {
				zero_run=false;
				if (zero_count>zero_max_count) {
					zero_max_count=zero_count;
					zero_max_index=zero_index;
				}
			}
		}
		if (zero_run && zero_count>zero_max_count) {
			zero_max_count=zero_count;
			zero_max_index=zero_index;
		}
		//SystemUtils.log(LoggerLevel.DEBUG,"Ip6Address: bytesToString(): zero index: "+zero_max_index+" ("+zero_max_count+")");
		
		StringBuffer sb=new StringBuffer();
		for (int i=0; i<zero_max_index; i++) {			
			sb.append(Integer.toString(addr[i],16));
			if (i<(zero_max_index-1)) sb.append(':');
		}
		if (zero_max_count>0) sb.append("::");
		for (int i=zero_max_index+zero_max_count; i<8; i++) {			
			sb.append(Integer.toString(addr[i],16));
			if (i<7) sb.append(':');
		}			
		return sb.toString();
	}
	
	
	// ************************* SUBNET PREFIXES *************************	
	
	/** Gets a subnet prefix.
	 * @param prefix starting network prefix
	 * @param subnet_len subnet prefix length
	 * @param subnet_value subnet value
	 * @return the new subnet prefix */
	public static IpPrefix subnet(IpPrefix prefix, int subnet_len, long subnet_value) {
		byte[] addr=new byte[prefix.prefixAddress().length()];
		prefix.getBytes(addr,0);
		if (subnet_len<prefix.prefixLength()) throw new RuntimeException("Subnet prefix length too short ("+subnet_len+"<"+prefix.prefixLength()+")");
		if (subnet_value>=(0x1<<(subnet_len-prefix.prefixLength()))) throw new RuntimeException("Subnet value too big ("+subnet_value+">="+(0x1<<(subnet_len-prefix.prefixLength()))+")");
		int len=subnet_len;
		while(len%8!=0) {
			subnet_value<<=1;
			len+=1;
		}
		int index=len/8-1;
		for (; subnet_value>0; index--) {
			addr[index]+=(byte)(subnet_value&0xff);
			subnet_value>>=8;
		}
		if (prefix instanceof Ip4Prefix) return new Ip4Prefix(addr,0,subnet_len);
		if (prefix instanceof Ip6Prefix) return new Ip6Prefix(addr,0,subnet_len);
		// else
		throw new RuntimeException("Unsupported prefix type: "+prefix.getClass().getSimpleName());		
	}

	/** Gets an address within a network prefix.
	 * @param prefix network prefix
	 * @param host_value host value (suffix)
	 * @return the new address */
	public static IpAddressPrefix addressPrefix(IpPrefix prefix, long host_value) {
		byte[] addr=new byte[prefix.prefixAddress().length()];
		prefix.getBytes(addr,0);
		int index=addr.length-1;
		for (; host_value>0; index--) {
			addr[index]+=(byte)(host_value&0xff);
			host_value>>=8;
		}
		if (prefix instanceof Ip4Prefix) return new Ip4AddressPrefix(addr,0,prefix.prefixLength());
		if (prefix instanceof Ip6Prefix) return new Ip6AddressPrefix(addr,0,prefix.prefixLength());
		// else
		throw new RuntimeException("Unsupported prefix type: "+prefix.getClass().getSimpleName());		
	}

	/** Gets an address within a network prefix.
	 * @param prefix network prefix
	 * @param host host address (suffix)
	 * @return the new address */
	public static IpAddressPrefix addressPrefix(IpPrefix prefix, String host) {
		if (prefix instanceof Ip4Prefix) return addressPrefix(prefix,new Ip4Address(host));
		if (prefix instanceof Ip6Prefix) return addressPrefix(prefix,new Ip6Address(host));
		// else
		throw new RuntimeException("Unsupported address type: "+prefix.getClass().getSimpleName());		
	}

	/** Gets an address within a network prefix.
	 * @param prefix network prefix
	 * @param host host address (suffix)
	 * @return the new address */
	public static IpAddressPrefix addressPrefix(IpPrefix prefix, IpAddress host) {
		int len=prefix.prefixAddress().length();
		if (len!=host.length()) throw new RuntimeException("Address length mismatch: "+len+"!="+host.length());
		byte[] addr=new byte[len];
		prefix.getBytes(addr,0);
		byte[] buf=host.getBytes();
		for (int i=0; i<addr.length; i++) addr[i]|=buf[i];
		if (prefix instanceof Ip4Prefix) return new Ip4AddressPrefix(addr,0,prefix.prefixLength());
		if (prefix instanceof Ip6Prefix) return new Ip6AddressPrefix(addr,0,prefix.prefixLength());
		// else
		throw new RuntimeException("Unsupported address type: "+prefix.getClass().getSimpleName());
	}
	
	
	// ************************* OTHERS *************************

	/** Computes the base 2 logarithm and return the lowest integer greater or equal to the result. 
	 * @param n the logarithm argument
	 * @return the lowest integer greater or equal to the Log2 of argument */
	public static int ceilLog2(long n) {
		//return (int)Math.ceil(Math.log(n)/Math.log(2));
		int val=0;
		for (n--; n>0; n>>=1) val++;
		return val;
	}

	/** Computes the base <i>k</k> logarithm, with <i>k</k> power of 2, and return the lowest integer greater or equal to the result. 
	 * @param p the Log2 of <i>k</k>, i.e. k=2^p
	 * @param n the logarithm argument
	 * @return the lowest integer greater or equal to the base <i>k</k> Log of argument */
	/*public static int ceilLogK(int p, long n) {
		//return (int)Math.ceil(Math.log(n)/Math.log(Math.pow(2,p)));
		if (p<1) throw new RuntimeException("The power P must be greater than 0 ("+p+")");
		int val=0;
		for (n--; n>0; n>>=p) val++;
		return val;
	}*/

}
