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


import it.unipr.netsec.ipstack.net.NetAddress;


/** IP network prefix.
 */
public interface IpPrefix extends NetAddress {
	
	/** Gets the prefix address.
	 * @return prefix address */
	public IpAddress prefixAddress();
	
	/** Gets the prefix length.
	 * @return prefix length */
	public int prefixLength();
	
	/** Gets the prefix mask.
	 * @return the prefix mask */
	public byte[] prefixMask();
}
