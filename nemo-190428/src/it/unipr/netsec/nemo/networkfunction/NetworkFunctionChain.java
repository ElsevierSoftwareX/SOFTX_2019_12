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

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

/** Chain of Network Functions
 */
public class NetworkFunctionChain extends NetworkFunction {

	/** Debug mode */
	public static boolean DEBUG=true; 
	
	/** Network functions */
	NetworkFunction[] network_functions;
	
	
	/** Creates a NetworkFunctionChain.
	 * @param network_functions array of network functions */
	public NetworkFunctionChain(NetworkFunction[] network_functions) {
		this.network_functions=network_functions;
	}
	

	@Override
	public int processPacket(byte[] buf, int len) {
		for (NetworkFunction nf: network_functions) {
			if (DEBUG) SystemUtils.log(LoggerLevel.DEBUG,NetworkFunctionChain.class,"qnum="+qnum+", NF="+nf.toString());
			len=nf.processPacket(buf,len);
			if (len==0) break;
		}
		return len;
	}

	
   /** The main method. */
	public static void main(String[] args) {
		
		try {
			final int qnum=Integer.parseInt(args[0]);
			final boolean accept;
			if (args[1].equalsIgnoreCase("accept")) accept=true;
			else
			if (args[1].equalsIgnoreCase("drop")) accept=false;
			else throw new RuntimeException("args[1] is neither 'accept' nor 'drop'.");
			
			new NetworkFunctionChain(new NetworkFunction[]{new FilterFunction(accept)}).runWithPromptForStopping(qnum);
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println("\nusage: java "+NetworkFunctionChain.class.getName()+" qnum accept|drop\n");
		}			
	}	

}
