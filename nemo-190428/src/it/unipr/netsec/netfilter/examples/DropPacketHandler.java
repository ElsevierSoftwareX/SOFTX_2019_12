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

package it.unipr.netsec.netfilter.examples;



import it.unipr.netsec.netfilter.*;



/** It drops or accepts all packets.
 */
public class DropPacketHandler implements PacketHandler {

	/** Whether accepting or dropping packets */
	boolean accept;
	
	/** Creates a queue handler.
	 * @param accept whether accepting or dropping packets */
	public DropPacketHandler(boolean accept) {
		this.accept=accept;
	}

	@Override
	public int processPacket(byte[] buf, int len) {
		if (accept) return len;
		else return 0;
	}

}
