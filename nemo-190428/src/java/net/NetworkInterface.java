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

package java.net;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.LoopbackInterface;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.netstack.NetStack;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.NoSuchElementException;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


public final class NetworkInterface {

	/** Debug mode */
	public static boolean DEBUG=true;
	
	/** Prints a debug message. */
	private static void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,NetworkInterface.class,str);
	}
	
	
	static int MTU=460;

	private int index;

	private NetInterface net_interface;

	
	NetworkInterface(int index, NetInterface net_interface) {
		debug("NetworkInterface(): "+net_interface);
		this.index=index;
		this.net_interface=net_interface;
	}

	public String getName() {
		return net_interface.getName();
	}
	
	static int DEBUG_COUNT=0;

	public Enumeration<InetAddress> getInetAddresses() {
		debug("getInetAddresses()");
		DEBUG_COUNT++;
		Address[] addrs=net_interface.getAddresses();
		final ArrayList<InetAddress> iaddrs=new ArrayList<InetAddress>();
		for (Address a: addrs) if (a instanceof IpAddress) iaddrs.add(((IpAddress)a).toInetAddress());
		debug("getInetAddresses(): "+iaddrs);
		return new Enumeration<InetAddress>(){
			int index=0;
			@Override
			public boolean hasMoreElements() {
				return (index<iaddrs.size());
			}			
			@Override
			public InetAddress nextElement() {
				if (index<iaddrs.size()) {
					debug("getInetAddresses(): nextElement(): "+index+", "+iaddrs.get(index));
					if (DEBUG_COUNT>=3) try { throw new RuntimeException("Debug"); } catch (Exception e) { e.printStackTrace(); System.exit(0); }
					return iaddrs.get(index++);
				}
				else {
					throw new NoSuchElementException();
				}
			}
		};
	}

	public java.util.List<InterfaceAddress> getInterfaceAddresses() {
		debug("getInetAddresses()");
		Address[] addrs=net_interface.getAddresses();
		ArrayList<InterfaceAddress> iaddrs=new ArrayList<InterfaceAddress>();
		for (Address a : addrs) {
			if (a instanceof Ip4AddressPrefix) iaddrs.add(new Ip4InterfaceAddressImpl((Ip4AddressPrefix)a));
			else
			if (a instanceof Ip6AddressPrefix) iaddrs.add(new Ip6InterfaceAddressImpl((Ip6AddressPrefix)a));
		}
		debug("getInetAddresses(): "+iaddrs.toString());
		return iaddrs;
	}

	/*public Enumeration<NetworkInterface> getSubInterfaces() {
		return null;
	}*/

	/*public NetworkInterface getParent() {
		return null;
	}*/

	public int getIndex() {
		return index;
	}

	public String getDisplayName() {
		return net_interface.getName();
	}

	public static NetworkInterface getByName(String name) throws SocketException {
		if (name==null) throw new NullPointerException();
		// else
		NetInterface[] ip4_interfaces=NetStack.IP4_LAYER.getNetInterfaces();
		for (int i=0; i<ip4_interfaces.length; i++) {
			NetInterface ni=ip4_interfaces[i];
			if (ni.getName().equalsIgnoreCase(name)) return new NetworkInterface(i,ni);
		}
		NetInterface[] ip6_interfaces=NetStack.IP6_LAYER.getNetInterfaces();
		for (int i=0; i<ip6_interfaces.length; i++) {
			NetInterface ni=ip6_interfaces[i];
			if (ni.getName().equalsIgnoreCase(name)) return new NetworkInterface(i,ni);
		}
		return null;
	}

	public boolean isUp() throws SocketException {
		return true;
	}

	public boolean isLoopback() throws SocketException {
		return net_interface instanceof LoopbackInterface;
	}

	public boolean isPointToPoint() throws SocketException {
		// TODO
		return false;
	}

	public boolean supportsMulticast() throws SocketException {
		// TODO
		return true;
	}

	public byte[] getHardwareAddress() throws SocketException {
		// TODO
		return null;
	}

	public int getMTU() throws SocketException {
		// TODO
		return MTU;
	}

	public boolean isVirtual() {
		// TODO
		return false;
	}

	public boolean equals(Object obj) {
		if (obj==null|| !(obj instanceof NetworkInterface)) return false;
		// else
		NetworkInterface ni=(NetworkInterface)obj;
		return net_interface.equals(ni.net_interface);
	}

	public int hashCode() {
		//return name==null? 0: name.hashCode();
		// TODO
		return net_interface.hashCode();
	}

	public String toString() {
		return net_interface.getName();
	}

	// STATIC METHODS:
	
	public static NetworkInterface getByIndex(int index) throws SocketException {
		debug("getByIndex()");
		if (index<0) throw new IllegalArgumentException("Interface index can't be negative");
		// else
		NetInterface[] net_interfaces=NetStack.IP4_LAYER.getNetInterfaces();
		return new NetworkInterface(index,net_interfaces[index]);
	}

	public static NetworkInterface getByInetAddress(InetAddress addr) throws SocketException {
		debug("getByInetAddress()");
		if (addr==null) throw new NullPointerException();
		if (!(addr instanceof Inet4Address || addr instanceof Inet6Address)) throw new IllegalArgumentException ("invalid address type");
		// TODO
		NetInterface[] net_interfaces=NetStack.IP4_LAYER.getNetInterfaces();
		if (addr instanceof Inet4Address) {
			IpAddress ipaddr=new Ip4Address((Inet4Address)addr);
			for (int i=0; i<net_interfaces.length; i++) {
				NetInterface ni=net_interfaces[i];
				if (ni.hasAddress(ipaddr)) return new NetworkInterface(i,ni);
			}
		}
		else
		if (addr instanceof Inet6Address) {
			IpAddress ipaddr=new Ip6Address((Inet6Address)addr);
			for (int i=0; i<net_interfaces.length; i++) {
				NetInterface ni=net_interfaces[i];
				if (ni.hasAddress(ipaddr)) return new NetworkInterface(i,ni);
			}
		}
		return null;
	}

	public static Enumeration<NetworkInterface> getNetworkInterfaces() throws SocketException {
		debug("getNetworkInterfaces()");
		final NetInterface[] net_interfaces=NetStack.IP4_LAYER.getNetInterfaces();
		debug("getNetworkInterfaces(): "+Arrays.toString(net_interfaces));
		return new Enumeration<NetworkInterface>(){
			int index=0;
			@Override
			public boolean hasMoreElements() {
				return index<net_interfaces.length;
			}
			@Override
			public NetworkInterface nextElement() {
				NetworkInterface ni=new NetworkInterface(index,net_interfaces[index]);
				index++;
				return ni;
			}
		};
	}

	static NetworkInterface getDefault() {
		debug("getDefault()");
		NetInterface[] net_interfaces=NetStack.IP4_LAYER.getNetInterfaces();
		if (net_interfaces==null || net_interfaces.length==0) return null;
		// else
		return new NetworkInterface(0,net_interfaces[0]);
	}
}
