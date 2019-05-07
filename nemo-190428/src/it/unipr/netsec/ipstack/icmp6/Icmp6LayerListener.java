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

package it.unipr.netsec.ipstack.icmp6;


import it.unipr.netsec.ipstack.ip6.Ip6Packet;


/** It listens for incoming ICMPv6 messages.
 */
public interface Icmp6LayerListener {

	/** When an ICMPv6 layer receives a new ICMPv6 message.
	 * @param icmp_layer the ICMPv6 layer
	 * @param ip_pkt the IPv6 packet containing the ICMPv6 message */
	public void onReceivedIcmpMessage(Icmp6Layer icmp_layer, Ip6Packet ip_pkt);
	
}
