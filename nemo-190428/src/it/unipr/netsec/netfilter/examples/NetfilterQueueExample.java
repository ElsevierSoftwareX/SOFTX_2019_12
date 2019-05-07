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

import java.io.BufferedReader;
import java.io.InputStreamReader;



/** Example program that creates a linux netfilter queue {@link it.unipr.netsec.netfilter.NetfilterQueue}
 * and processes all queued packets using a {@link IcmpPacketHandler} packet handler.
 * <p>
 * At the sender side, in order to pass and filter all ICMP outgoing packets you should use the following command:
 * <pre>
 * sudo iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0
 * </pre>
 * <p>
 * While at the receiver side, for capturing all incoming modified packets and restoring the original ICMP packets you should use the command:
 * <pre>
 * sudo iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0
 * </pre>
 */
public class NetfilterQueueExample {

	
	/** No constructor is available. */
	private NetfilterQueueExample() {
	}
	

   /** The main method. */
	public static void main(String[] args) {
		
		boolean verbose=args.length>0? args[0].equals("-v") : false;
		
		final NetfilterQueue qh=new NetfilterQueue(0,new IcmpPacketHandler(verbose));

		(new Thread() { public void run() { qh.start(); }}).start();
		
		System.out.println("Press 'Return' to stop.");
		BufferedReader in=new BufferedReader(new InputStreamReader(System.in));
		try { in.readLine(); } catch (Exception e) { e.printStackTrace(); }
		qh.stop();
	}	

}
