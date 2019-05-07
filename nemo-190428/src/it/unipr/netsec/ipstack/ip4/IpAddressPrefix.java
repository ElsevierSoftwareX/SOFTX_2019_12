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



/** Internet Protocol version 4 (IPv4) address with prefix length.
 * <p>
 * It extends class {@link Ip4Address} by simply adding prefix length information.
 */
public interface IpAddressPrefix extends IpAddress {

	/** Gets the prefix length.
	 * @return prefix length */
	public int getPrefixLength();

	/** Gets the network prefix.
	 * @return the network prefix */
	public IpPrefix getPrefix();

	/** Gets string representation of the IP address including the prefix length.
	 * @return the IP address followed by the prefix length (e.g. "192.168.1.5/24" in case of IPv4) */
	public String toStringWithPrefixLength();
}
