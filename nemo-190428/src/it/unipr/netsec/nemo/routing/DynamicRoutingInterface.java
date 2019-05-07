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

package it.unipr.netsec.nemo.routing;

import it.unipr.netsec.ipstack.net.Packet;

/** Node interface for the dynamic routing.
 * <p>
 * It allows to instruct the routing of the node
 * and to let the routing mechanism exchange routing information with other nodes.
 */
public interface DynamicRoutingInterface {

	/** Updates routing information.
	 * @param ra array of the new routes */
	public void updateRouting(RouteInfo[] ra);

	/** Sends a packet.
	 * @param pkt a packet to send */
	public void sendPacket(Packet pkt);

}
