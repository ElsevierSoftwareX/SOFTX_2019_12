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

package it.unipr.netsec.nemo.networkfunction;


import it.unipr.netsec.netfilter.NetfilterQueue;
import it.unipr.netsec.netfilter.PacketHandler;

import java.io.BufferedReader;
import java.io.InputStreamReader;


/** Generic Network Function.
 * <p>
 * Method {{@link NetworkFunction#run(int)} attaches this function to a linux netfilter queue (NFQUEUE).
 * After that, all queued packets are processed by the method {@link NetworkFunction#processPacket(byte[], int)}.
 * <p>
 * Depending on where the NFQUEUE is added to the netfilter it can processes incoming or outgoing packets.
 * <p>
 * For example, in order to process all outgoing packets you could use the following command:
 * <pre>
 * sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
 * </pre>
 * <p>
 * Instead, for capturing all incoming packets you could use the command:
 * <pre>
 * sudo iptables -A PREROUTING -j NFQUEUE --queue-num 0
 * </pre>
 * For capturing all input packets you could use the command:
 * <pre>
 * sudo iptables -A INPUT -j NFQUEUE --queue-num 0
 * </pre>
 */
public abstract class NetworkFunction implements PacketHandler {

	/** Netfilter queue handler */
	NetfilterQueue qh=null;

	/** Netfilter queue number */
	int qnum=-1;

	
	/** Attaches this network function to a given netfilter queue and runs it.
    * @param qnum netfilter queue number */
	public void run(int qnum) {
		this.qnum=qnum;
		qh=new NetfilterQueue(qnum,this);
		(new Thread() { public void run() { qh.start(); }}).start();
	}

	
	/** Stops this network function. */
	public void stop() {
		if (qh!=null) {
			qh.stop();
			qh=null;
		}
	}	

	
	/** Attaches this network function to a given netfilter queue, runs it, waits until 'Enter' is pressed, and finally stops the network function.
	 * Note that this is a blocking method. */
	public void runWithPromptForStopping(int qnum) {
		run(qnum);
		System.out.println("Press 'Enter' to stop.");
		try { new BufferedReader(new InputStreamReader(System.in)).readLine(); } catch (Exception e) { e.printStackTrace(); }
		stop();
	}

		
	@Override
	public String toString()  {
		return this.getClass().getSimpleName();
	}
}
