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

package it.unipr.netsec.ipstack.netstack;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4LoopbackInterface;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.link.EthTunnelInterface;
import it.unipr.netsec.ipstack.link.Link;
import it.unipr.netsec.ipstack.link.LinkInterface;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.tuntap.Ip4TapInterface;
import it.unipr.netsec.tuntap.Ip4TunInterface;
import it.unipr.netsec.tuntap.TuntapSocket;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;


/** IP configuration based on Linux '{@code ip addr add}' and '{@code ip route add}' commands.
 */
public class LinuxIp4Configuration implements NetConfiguration {

	private static HashMap<String,Link> VIRTUAL_LINKS=new HashMap<String,Link>();

	public static SocketAddress DEFAULT_UDPTUNNEL_SOADDR=new SocketAddress("127.0.0.1:7000");

	
	private HashMap<String,NetInterface> net_interfaces=new HashMap<String,NetInterface>();

	private ArrayList<Route> routes=new ArrayList<Route>();

	
	/** Creates a new configuration. */
	public LinuxIp4Configuration() {
		net_interfaces.put("lo",new Ip4LoopbackInterface());
	}

	/** Creates a new configuration.
	 * @param file_name name of the configuration file 
	 * @throws IOException */
	public LinuxIp4Configuration(String file_name) throws IOException {
		BufferedReader config=new BufferedReader(new FileReader(file_name));
		String line;
		while ((line=config.readLine())!=null) {
			line=line.trim();
			if (line.length()>0 && !line.startsWith("#")) add(line);
		}
		config.close();
	}

	@Override
	public NetConfiguration add(String name, NetInterface ni) {
		net_interfaces.put(name,ni);
		return this;
	}

	@Override
	public NetConfiguration add(Route r) {
		routes.add(r);
		return this;
	}
	
	@Override
	public LinuxIp4Configuration add(String command) throws IOException {
		String[] tokens=command.split("\\s");
		if (tokens.length==6 && tokens[0].equals("ip") && tokens[1].startsWith("addr") && tokens[2].equals("add") && tokens[4].equals("dev")) {
			// ip addr add <ipaddr/prefixlen> dev <interface>
			Ip4AddressPrefix addr_prefix=new Ip4AddressPrefix(tokens[3]);
			String dev=tokens[5];
			if (dev.startsWith("eth")) {
				String network=addr_prefix.getPrefix().toString();
				Link link;
				if (VIRTUAL_LINKS.containsKey(network)) link=VIRTUAL_LINKS.get(network);
				else VIRTUAL_LINKS.put(network,link=new Link());
				NetInterface eth=new LinkInterface(link,addr_prefix);
				add(dev,eth);
			}
			else
			if (dev.startsWith("tun") || dev.startsWith("utun")) {
				NetInterface tun=new Ip4TunInterface(dev,addr_prefix);
				add(dev,tun);
			}
			else
			if (dev.startsWith("tap")) {
				NetInterface tun=new Ip4TapInterface(dev,addr_prefix);
				add(dev,tun);
			}
			else
			if (dev.startsWith("udptunnel")) {
				SocketAddress hub_soaddr=DEFAULT_UDPTUNNEL_SOADDR;
				int index=dev.indexOf('/');
				if (index>0) {
					hub_soaddr=new SocketAddress(dev.substring(index+1));
					dev=dev.substring(index);
				}
				NetInterface udptunnel=new EthTunnelInterface(addr_prefix,hub_soaddr);
				add(dev,udptunnel);
			}
			// else
		}
		else
		if (tokens.length==8 && tokens[0].equals("ip") && tokens[1].startsWith("route") && tokens[2].equals("add") && tokens[4].equals("via") && tokens[6].equals("dev")) {
			// ip route add <netaddr/prefixlen> via <router> dev <interface>
			Ip4Prefix dest=new Ip4Prefix(tokens[3]);
			Ip4Address router=new Ip4Address(tokens[5]);					
			String dev=tokens[7];
			Route route=new Route(dest,router,net_interfaces.get(dev));
			add(route);
		}
		else {
			throw new IOException("Unsupported configuration command: "+command);
		}
		return this;
	}
	
	@Override
	public NetInterface[] getNetInterfaces() {
		return net_interfaces.values().toArray(new NetInterface[]{});
	}

	@Override
	public Route[] getRoutes() {
		return routes.toArray(new Route[]{});
	}

}
