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

package it.unipr.netsec.ipstack.tcp;



/** It listens for incoming TCP packets.
 */
public interface TcpLayerListener {

	/** When a new TCP packet is received.
	 * @param tcp_layer the TCP layer
	 * @param tcp_pkt the TCP packet */
	public void onReceivedPacket(TcpLayer tcp_layer, TcpPacket tcp_pkt);
	
}
