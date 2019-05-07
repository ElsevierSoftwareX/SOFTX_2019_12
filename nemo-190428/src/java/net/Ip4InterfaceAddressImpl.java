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

package java.net;


import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;


class Ip4InterfaceAddressImpl extends InterfaceAddress {
	
	Ip4AddressPrefix address_prefix;

	
	public Ip4InterfaceAddressImpl(Ip4AddressPrefix address_prefix) {
		this.address_prefix=address_prefix;
	}

	public boolean equals(Object obj) {
		// TODO
		if (!(obj instanceof Ip4InterfaceAddressImpl)) return false;
		// else
		Ip4InterfaceAddressImpl ia=(Ip4InterfaceAddressImpl)obj;
		return address_prefix.equals(ia.address_prefix);
	}
	
	public InetAddress getAddress() {
		return address_prefix.toInetAddress();
	}
	
	public InetAddress getBroadcast() {
		// TODO
		return null;
	}
	
	public short getNetworkPrefixLength() {
		return (short)address_prefix.getPrefixLength();		
	}
	
	public int hashCode() {
		// TODO
		return address_prefix.hashCode();
	}
	
	public String toString() {
		// TODO
		return address_prefix.toStringWithPrefixLength();
	}

}
