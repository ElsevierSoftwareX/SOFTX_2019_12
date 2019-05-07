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


import java.net.InetAddress;

import it.unipr.netsec.ipstack.net.Address;


/** IP address.
 */
public interface IpAddress extends Address {
	
	/** Converts this address to {@link java.net.InetAddress}.
	 * @return a {@link java.net.InetAddress} */
	public InetAddress toInetAddress();
	
	/** Gets the address length.
	 * @return the length (in bytes) */
	public int length();

	/** Checks whether it is a multicast or broadcast address.
	 * @return <i>true</i> if it is a multicast or broadcast address */
	public boolean isMulticast();

	/** Gets the protocol version.
	 * @return the version */
	//public int version();
	
}
