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

package it.unipr.netsec.ipstack.ethernet;


import java.util.Arrays;

import it.unipr.netsec.ipstack.net.Address;


/** Ethernet address.
 */
public class EthAddress implements Address {

	/** Broadcast address */
	public static final EthAddress BROADCAST_ADDRESS=new EthAddress(new byte[]{(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff});

	
	/** The address as array of bytes */
	byte[] addr=null;
	
	
	
	/** Creates a new address.
	 * @param buf byte array containing the address */
	public EthAddress(byte[] buf) {
		this.addr=new byte[6];
		System.arraycopy(buf,0,this.addr,0,6);
	}
	

	/** Creates a new address.
	 * @param buf byte array containing the address
	 * @param off the offset within the buffer */
	public EthAddress(byte[] buf, int off) {
		addr=new byte[6];
		System.arraycopy(buf,off,this.addr,0,6);
	}

	
	/** Creates a new address.
	 * @param str_addr the address in hexadecimal format (e.g. "01:02:03:04:05:06") */
	public EthAddress(String str_addr) {
		addr=new byte[6];
		//DataPacket.hexStringToBytes(str_addr,addr,0);
		int index=0;
		for (int i=0; i<6; i++) {
			while ((str_addr.charAt(index))==':') index++;
			addr[i]=(byte)Integer.parseInt(str_addr.substring(index,index+2),16);
			index+=2;
		}
		
	}
	
	
	@Override
	public boolean equals(Object o) {
		EthAddress addr=null;
		if (o instanceof EthAddress) addr=(EthAddress)o;
		else
			if (o instanceof String) addr=new EthAddress((String)o);
			else
				if (o instanceof byte[]) addr=new EthAddress((byte[])o);
				else
					return false;
		return Arrays.equals(getBytes(),addr.getBytes());
	}

	
	@Override
	public int hashCode() {
		return Arrays.hashCode(getBytes());
	}

	
	@Override
	public String toString() {
		//return DataPacket.bytesToHexString(addr);
		StringBuffer sb=new StringBuffer();
		for (int i=0; i<6; i++) {
			sb.append(Integer.toHexString((addr[i]>>4)&0x0F));
			sb.append(Integer.toHexString(addr[i]&0x0F));
			if (i<5) sb.append(':');
		}
		return sb.toString();

	}

	
	@Override
	public byte[] getBytes() {
		return addr;
	}


	@Override
	public int getBytes(byte[] buf, int off) {
		System.arraycopy(addr,0,buf,off,6);
		return 6;
	}
	
}
