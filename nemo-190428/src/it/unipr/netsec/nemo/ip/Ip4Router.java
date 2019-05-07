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

package it.unipr.netsec.nemo.ip;


import java.util.ArrayList;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Node;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetAddress;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;
import it.unipr.netsec.nemo.routing.LinkStateInfo;
import it.unipr.netsec.nemo.routing.RouteInfo;
import it.unipr.netsec.nemo.routing.DynamicRouting;
import it.unipr.netsec.nemo.routing.DynamicRoutingInterface;


/** IPv4 Router.
 */
public class Ip4Router extends Ip4Node {

	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	void debug(String str) {
		//SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
		SystemUtils.log(LoggerLevel.DEBUG,Ip4Router.class.getSimpleName()+"["+getID()+"]: "+str);
	}


	/** Virtual link used for assigning Unique Local Addresses (ULAs) */
	//private static IpLink LOOPBACK_ADDRESSES=new IpLink(new Ip4Prefix("10.254.0.0/16"));
	private static IpLink LOOPBACK_ADDRESSES=new IpLink(new Ip4Prefix("172.31.0.0/16"));

	/** Address used as router identifier */
	Address loopback_addr;
	
	/** Whether is paused */
	boolean paused=false;
	
	/** Dynamic routing mechanism */
	DynamicRouting dynamic_routing=null;


	/** Creates a new router.
	 * @param loopback_addr address used as router identifier; if <code>null</code>, it is automatically assigned from the unique set {@link #LOOPBACK_ADDRESSES}
	 * @param net_interfaces network interfaces */
	public Ip4Router(Address loopback_addr, NetInterface[] net_interfaces) {
		super(net_interfaces);
		setForwarding(true);
		//if (loopback_addr==null) loopback_addr=net_interfaces[0].getAddresses()[0];
		if (loopback_addr==null) loopback_addr=LOOPBACK_ADDRESSES.nextAddressPrefix();
		this.loopback_addr=loopback_addr;
	}
	
	/** Creates a new router.
	 * Loopback address is automatically assigned.
	 * @param net_interfaces network interfaces */
	public Ip4Router(NetInterface[] net_interfaces) {
		this(null,net_interfaces);
	}
	
	/** Creates a new router.
	 * Addresses are automatically assigned.
	 * @param links the IP links the router is attached to */
	public Ip4Router(IpLink[] links) {
		this(null,IpLinkInterface.createLinkInterfaceArray(links));
		NetInterface[] ni=getNetInterfaces();
		for (int i=0; i<ni.length; i++) {
			links[i].addRouter((Ip4Address)ni[i].getAddresses()[0]);
		}
	}
	
	/** Gets the loopback address.
	 * @return the address */
	public Address getLoopbackAddress() {
		return loopback_addr;
	}

	/** Pauses the router.
	 * @param paused <i>true</i> to pause, <i>false</i> to resume */
	public void pause(boolean paused) {
		this.paused=paused;
	}

	/** Sets dynamic routing.
	 * @param dynamic_routing the dynamic routing mechanism */
	public void setDynamicRouting(DynamicRouting dynamic_routing) {
		if (this.dynamic_routing!=null) {
			this.dynamic_routing.disconnect(loopback_addr);
		}
		this.dynamic_routing=dynamic_routing;
		if (dynamic_routing!=null) {
			ArrayList<LinkStateInfo> lsa=new ArrayList<LinkStateInfo>();
			for (NetInterface ni: getNetInterfaces()) {
				for (Address addr: ni.getAddresses()) {
					if (addr instanceof Ip4AddressPrefix) {
						Ip4AddressPrefix ip_addr_prefix=(Ip4AddressPrefix)addr;
						lsa.add(new LinkStateInfo(ip_addr_prefix,ip_addr_prefix.getPrefix(),1));
					}
				}
			}
			dynamic_routing.connect(loopback_addr,lsa.toArray(new LinkStateInfo[]{}),new DynamicRoutingInterface() {
				@Override
				public void updateRouting(RouteInfo[] ra) {
					updateRoutingTable(ra);	
				}
				@Override
				public void sendPacket(Packet pkt) {
					Ip4Router.this.sendPacket(pkt);
				}
			});
		}
	}
	
	@Override
	public boolean hasAddress(Address addr) {
		if (addr.equals(loopback_addr)) return true;
		return super.hasAddress(addr);
	}
	
	@Override
	protected void processReceivedPacket(NetInterface ni, Packet pkt) {
		if (!paused) {
			if (dynamic_routing!=null) pkt=dynamic_routing.processReceivedPacket(loopback_addr,pkt);
			if (pkt!=null) super.processReceivedPacket(ni,pkt);
		}
	}

	@Override
	public void sendPacket(Packet pkt) {
		if (!paused) {
			super.sendPacket(pkt);			
		}
	}

	/** Updates the routing table according to the information obtained from the routing mechanism.
	 * @param ra array of the new routes */
	private synchronized void updateRoutingTable(RouteInfo[] ra) {
		RoutingTable rt=getRoutingTable();
		rt.removeAll();
		for (RouteInfo ri: ra) {
			NetAddress dest=new Ip4Prefix(ri.getDestination());
			Ip4Address next_hop=ri.getNextHop()!=null? new Ip4Address(ri.getNextHop()) : null;
			Ip4Address interface_addr=new Ip4Address(ri.getInterfaceAddress());
			NetInterface net_interface=null;
			for (NetInterface ni: getNetInterfaces()) {
				if (ni.hasAddress(interface_addr)) {
					net_interface=ni;
					break;
				}
			}
			rt.add(new Route(dest,next_hop,net_interface));
		}
		if (DEBUG) debug("updateRoutingTable():\n"+rt);
	}

	/*@Override
	public String toString() {
		return getClass().getSimpleName()+'['+loopback_addr+']';
	}*/

	@Override
	protected String getID() {
		return ""+loopback_addr;
	}

}
