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

package it.unipr.netsec.ipstack.net;


import java.util.ArrayList;

import org.zoolu.util.Random;


/** A network interface for sending and receiving packets.
 * <p>
 * It may have one or more interface addresses.
 */
public abstract class NetInterface {

	/** Length of the interface id */
	private static int ID_LEN=8;

	/** Interface id; if name is null, it is a randomly generated hex string */
	private String id=null;
	
	/** Interface name */
	private String name=null;
	
	/** Interface addresses */
	protected ArrayList<Address> addresses=new ArrayList<Address>();
	
	/** Interface listeners */
	protected ArrayList<NetInterfaceListener> listeners=new ArrayList<NetInterfaceListener>();
	

	
	/** Creates a new interface.
	 * @param name interface name */
	protected NetInterface(String name) {
		this(name,(Address)null);
	}

	
	/** Creates a new interface.
	 * @param addr interface address */
	protected NetInterface(Address addr) {
		this(null,addr);
	}

	
	/** Creates a new interface.
	 * @param name interface name
	 * @param addr interface address */
	protected NetInterface(String name, Address addr) {
		this.name=name;
		if (addr!=null) addresses.add(addr);
	}

	
	/** Creates a new interface.
	 * @param addrs interface addresses */
	protected NetInterface(Address[] addrs) {
		this(null,addrs);
	}

	/** Creates a new interface.
	 * @param name interface name
	 * @param addrs interface addresses */
	protected NetInterface(String name, Address[] addrs) {
		if (name!=null) this.name=name; else id=Random.nextHexString(ID_LEN);
		if (addrs!=null) for (Address a : addrs) addresses.add(a);
	}

	
	/** Adds a listener to this interface for receiving incoming packets targeted to this interface.
	 * @param listener interface listener to be added */
	public void addListener(NetInterfaceListener listener) {
		synchronized (listeners) {
			listeners.add(listener);
		}
	}
	
	
	/** Removes a listener.
	 * @param listener interface listener to be removed */
	public void removeListener(NetInterfaceListener listener) {
		synchronized (listeners) { 
			for (int i=0; i<listeners.size(); i++) {
				NetInterfaceListener li=listeners.get(i);
				if (li==listener) {
					listeners.remove(i);
				}
			}
		}
	}

	
	/** Gets all interface listeners.
	 * @return array of listeners */
	public NetInterfaceListener[] getListeners() {
		synchronized (listeners) { 
			return listeners.toArray(new NetInterfaceListener[0]);
		}
	}

		
	/** Adds an interface address.
	 * @param addr the address */
	public void addAddress(Address addr) {
		synchronized (addresses) {
			addresses.add(addr);
		}
	}

	
	/** Removes an interface address.
	 * @param addr the address */
	public void removeAddress(Address addr) {
		synchronized (addresses) {
			for (int i=0; i<addresses.size(); i++) {
				Address a=addresses.get(i);
				if (a.equals(addr)) {
					addresses.remove(a);
				}
			}
		}		
	}
	
	/** Gets interface name.
	 * @return the interface name */
	public String getName() {
		if (name!=null) return name;
		else return getId();
	}

	/** Gets all interface addresses.
	 * @return the addresses */
	public Address[] getAddresses() {
		synchronized (addresses) { 
			return addresses.toArray(new Address[0]);
		}
	}
	
	/** Whether a given address belongs to this interface.
	 * @param addr the address
	 * @return <i>true</i> if the address belongs to this interface */
	public boolean hasAddress(Address addr) {
		synchronized (addresses) { 
			for (Address a : addresses) {
				if (a.equals(addr)) return true;
			}
		}
		return false;
	}

	
	/** Sends a packet.
	 * @param pkt the packet to be sent
	 * @param dest_addr the address of the destination interface */
	public abstract void send(Packet pkt, Address dest_addr);	

		
	/** Closes the interface. */
	public void close() {
		listeners.clear();
	}
	
	
	/** Gets an identification string for this interface.
	 * @return the first address associated to this interface */
	protected String getId() {
		if (name!=null) return name;
			else if (addresses.size()>0) return addresses.get(0).toString();
				else return id;
	}

	
	@Override	
	public String toString() {
		return getClass().getSimpleName()+'['+getId()+']';
	}

}
