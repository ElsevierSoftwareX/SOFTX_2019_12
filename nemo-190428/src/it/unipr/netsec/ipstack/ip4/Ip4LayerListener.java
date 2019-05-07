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



/** Listener of the IPv4 layer.
 * It listens for incoming packets.
 */
public interface Ip4LayerListener {

	/** When a new packet is received.
	 * @param ip_layer the IP layer
	 * @param ip_pkt the received packet */
	public void onReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt);
	
}
