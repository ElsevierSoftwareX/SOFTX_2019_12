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

package it.unipr.netsec.netfilter;


/** It creates a netfilter IP queue and attaches to it a {@link PacketHandler} for processing queued packets.
 */
public class NetfilterQueue {

	
	/** Loads the qfilter library */
	static {
		try { System.loadLibrary("qfilter-64"); }
		catch (Error e1) {
			try { System.loadLibrary("qfilter-32"); }
			catch (Error e2) {
				System.loadLibrary("qfilter");
			}
		}
	}
		
	/** Netfilter queue connection handle */
	long handle;
	
	/** Queue handler */
	//long queqe_handle;

	/** Packet handler */
	PacketHandler packet_handler;
	
	/** The number of the queue to bind to */
	int num;

	
	
	/** Creates a new queue.
	 * @param num the number of the queue to bind to
	 * @param packet_handler the packet handler */
	public NetfilterQueue(int num, PacketHandler packet_handler) {
		this.num=num;
		this.packet_handler=packet_handler;
		this.handle=open();
		//this.queqe_handle=createQueue(handle,num,packet_handler);
	}
	
	/** Starts processing queued packets. */
	public void start() {
		run(handle,num,packet_handler);
	}

	/** Stops processing queued packets and removes the queue handler. */
	public void stop() {
		//destroyQueue(queqe_handle);
		close(handle);
	}

	/** Opens a nfqueue handler.
	 * This function obtains a netfilter queue connection handle. When you are finished with the handle returned by this function, you should destroy it by calling nfq_close(). A new netlink connection is obtained internally and associated with the queue connection handle returned.
	 * @return a pointer to a new queue handle or 0 on failure */
	private native long open();

	/** Closes a nfqueue handler.
	 * @param handle netfilter queue connection handle obtained via call to nfq_open() */
	private native void close(long handle);

	/** Creates a new queue handle.
	 * @param h netfilter queue connection handle obtained via call to open() 
	 * @param num the number of the queue to bind to
	 * @return a pointer to the newly created queue */
	//private native long createQueue(long handle, int num, PacketHandler packet_handler);
	
	/** Destroys a queue handle.
	 * @param queqe_handle queue handle that we want to destroy created via createQueue() */
	//private native void destroyQueue(long queqe_handle);

	/** Processes incoming packets.
	 * @param the queue handle
	 * @param num the number of the queue to bind to
	 * @param packet_handler the packet handler */
	private native int run(long handle, int num, PacketHandler packet_handler);

	
}
