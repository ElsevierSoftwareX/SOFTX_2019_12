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

package it.unipr.netsec.nemo.link;


import java.util.ArrayList;
import java.util.List;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.IpPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6Prefix;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;
import it.unipr.netsec.ipstack.util.IpAddressUtils;
import it.unipr.netsec.nemo.ip.Ip4Host;
import it.unipr.netsec.nemo.ip.Ip4Router;
import it.unipr.netsec.nemo.ip.Ip6Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.ip.IpLinkInterface;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.sdn.SdnRouting;
import it.unipr.netsec.simulator.scheduler.VirtualClock;


/** Creates IP networks with some well-known topologies.
 * <p>
 * Simple topologies like <i>linear</i>, <i>Manhattan</i>, and <i>n-ary tree</i> have been implemented.
 * <p>
 * IP addresses and routing-tables of all nodes are properly set-up.
 * For the loopback addresses, a pre-configured {@link #CORE_LOCAL_LINK_PREFIX4 private address block (IPv4)} or {@link #CORE_LOCAL_LINK_PREFIX6 ULA addresses (IPv6)} are used.
 */
public class NetworkBuilder {

	/** IPv4 prefix used for configuring core IPv4 router addresses (by default it uses IPv4 private addresses). */
	public static IpPrefix CORE_LOCAL_LINK_PREFIX4=new Ip4Prefix("10.128.0.0",9);
	
	/** IPv6 prefix used for configuring core IPv6 router addresses (by default it uses a ULA prefix). */
	public static IpPrefix CORE_LOCAL_LINK_PREFIX6=new Ip6Prefix("fd::",16);

	
	/** reates a linear topology with N routers, and N+1 links.
	 * @param n the number of routers
	 * @param bit_rate link bit rate
	 * @param net_prefix network prefix
	 * @return the new network */
	public static Network linearIpNetworkAlt(int n, long bit_rate, IpPrefix net_prefix) {
		// create all links
		IpLink[] links=new IpLink[n+1];
		for (int i=0; i<n+1; i++) links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,24,i+1));	
		// dynamic routing
		SdnRouting dynamic_routing=new SdnRouting(ShortestPathAlgorithm.DIJKSTRA);
		// create all routers
		Ip4Router[] routers=new Ip4Router[n];	
		for (int i=0; i<n; i++) {
			routers[i]=new Ip4Router(new IpLink[]{links[i],links[i+1]});
			routers[i].setDynamicRouting(dynamic_routing);
		}	
		// update all routing tables
		dynamic_routing.updateAllNodes();
		return new Network(routers,links);
	}

	
	/** Creates a linear topology with n routers and n+1 links.
	 * The link addresses are automatically assigned starting from the given supernet prefix.
	 * <p>
	 * No distinction is done between core and access links; all links are considered access links.
	 * <p>
	 * The router addresses are assigned by giving
	 * host id 1 to the router attached to the first link,
	 * host id 1 to the router on the left of each link,
	 * host id 2 to the router on the right of each link, except for first link.
	 * Note: the first link does not have a left router, the last link does not have a right router.
	 * <p>
	 * The routing tables are filled with the entire list of links (no supernetting is used).
	 * <p>
	 * The network is composed by IPv4 or Ipv6 routers depending on the type of the prefix address.
	 * @param n the number of routers
	 * @param bit_rate link bit rate
	 * @param net_prefix network prefix
	 * @return the new network */
	public static Network linearIpNetwork(int n, long bit_rate, IpPrefix net_prefix) {
		IpPrefix loopback_prefix=net_prefix instanceof Ip4Prefix? CORE_LOCAL_LINK_PREFIX4 : CORE_LOCAL_LINK_PREFIX6;
		int len=net_prefix.prefixLength()+IpAddressUtils.ceilLog2(n+2);

		// Links:
		IpLink[] links=new IpLink[n+1];
		for (int i=0; i<=n; i++) links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,len,i+1));
		
		// Routers:		
		Node[] routers=new Node[n];
		for (int i=0; i<n; i++) {
			// ni0 = left interface, ni1 = right interface
			DataLinkInterface ni0=new DataLinkInterface(links[i],IpAddressUtils.addressPrefix(links[i].getPrefix(),i==0? 1 : 2));
			DataLinkInterface ni1=new DataLinkInterface(links[i+1],IpAddressUtils.addressPrefix(links[i+1].getPrefix(),1));
			Address name=IpAddressUtils.addressPrefix(loopback_prefix,i+1);
			if (net_prefix instanceof Ip6Prefix) routers[i]=new Ip6Router(name,new DataLinkInterface[]{ni0,ni1});
			else routers[i]=new Ip4Router(name,new DataLinkInterface[]{ni0,ni1});
			links[i].addRouter((IpAddress)ni0.getAddresses()[0]);
			links[i+1].addRouter((IpAddress)ni1.getAddresses()[0]);
			RoutingTable rt=(RoutingTable)routers[i].getRoutingFunction();
			rt.add(new Route(IpAddressUtils.subnet(net_prefix,len,i+1),null,ni0));
			rt.add(new Route(IpAddressUtils.subnet(net_prefix,len,i+2),null,ni1));
			for (int j=0; j<=n; j++) {
				IpPrefix dest_prefix=links[j].getPrefix();
				if (j<i) rt.add(new Route(dest_prefix,IpAddressUtils.addressPrefix(links[i].getPrefix(),1),ni0));
				else
				if (j>(i+1)) rt.add(new Route(dest_prefix,IpAddressUtils.addressPrefix(links[i+1].getPrefix(),2),ni1));					
			}
		}
		return new Network(routers,links);
	}
	
	
	/** Creates a rectangular topology (Manhattan) with n*m routers and 2(n*m)+n+m links.
	 * The link addresses are automatically assigned starting from the given supernet prefix.
	 * <p>
	 * No distinction is done between core and access links; all links are considered access links.
	 * <p>
	 * The router addresses are assigned by giving
	 * host id 1 to the router on the south of the link,
	 * host id 2 to the router on the east,
	 * host id 3 to the router on the west, and
	 * host id 4 to the router on the north.
	 * <p>
	 * The routing tables are filled with the entire list of links (no supernetting is used).
	 * <p>
	 * The network is composed by IPv4 or Ipv6 routers depending on the type of the prefix address.
	 * @param n the number of rows
	 * @param m the number of columns
	 * @param bit_rate link bit rate
	 * @param net_prefix network prefix
	 * @return the new network */
	public static Network manhattanIpNetwork(int n, int m, long bit_rate, IpPrefix net_prefix) {
		IpPrefix loopback_prefix=net_prefix instanceof Ip4Prefix? CORE_LOCAL_LINK_PREFIX4 : CORE_LOCAL_LINK_PREFIX6;
		// Links:
		int num_of_links=2*n*m+n+m; // 2n^2 +2n
		int len=net_prefix.prefixLength()+IpAddressUtils.ceilLog2(num_of_links+1);

		IpLink[] links=new IpLink[num_of_links];
		for (int i=0; i<num_of_links; i++) links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,len,i+1));
		
		// Routers:		
		int num_of_nodes=n*m;
		Node[] routers=new Node[num_of_nodes];
		for (int i=0; i<n; i++) {
			for (int j=0; j<m; j++) {
				IpLink link0=links[i*(2*m+1)+j]; // north
				IpLink link1=links[i*(2*m+1)+m+j]; // west
				IpLink link2=links[i*(2*m+1)+m+j+1]; // east
				IpLink link3=links[i*(2*m+1)+2*m+1+j]; // south
				DataLinkInterface[] eth=new DataLinkInterface[4];
				eth[0]=new DataLinkInterface(link0,IpAddressUtils.addressPrefix(link0.getPrefix(),1)); // north
				eth[1]=new DataLinkInterface(link1,IpAddressUtils.addressPrefix(link1.getPrefix(),2)); // west
				eth[2]=new DataLinkInterface(link2,IpAddressUtils.addressPrefix(link2.getPrefix(),3)); // east
				eth[3]=new DataLinkInterface(link3,IpAddressUtils.addressPrefix(link3.getPrefix(),4)); // south
				//String name="R_"+i+","+j;
				Address loopback_addr=IpAddressUtils.addressPrefix(loopback_prefix,i*m+j+1);
				if (net_prefix instanceof Ip6Prefix) routers[i*m+j]=new Ip6Router(loopback_addr,eth);
				else routers[i*m+j]=new Ip4Router(loopback_addr,eth);
				link0.addRouter((IpAddress)eth[0].getAddresses()[0]);
				link1.addRouter((IpAddress)eth[1].getAddresses()[0]);
				link2.addRouter((IpAddress)eth[2].getAddresses()[0]);
				link3.addRouter((IpAddress)eth[3].getAddresses()[0]);
				RoutingTable rt=(RoutingTable)routers[i*m+j].getRoutingFunction();
				rt.add(new Route(link0.getPrefix(),null,eth[0]));
				rt.add(new Route(link1.getPrefix(),null,eth[1]));
				rt.add(new Route(link2.getPrefix(),null,eth[2]));
				rt.add(new Route(link3.getPrefix(),null,eth[3]));
				for (int k=0; k<num_of_links; k++) {
					IpPrefix dest_prefix=links[k].getPrefix();
					IpAddress gw=null;
					DataLinkInterface eth_out=null;
					int row=k/(m+n+1);
					int column=(k-row*(n+m+1));
					if (column>=m) column-=m;
					if (row<i) {
						gw=IpAddressUtils.addressPrefix(link0.getPrefix(),4);
						eth_out=eth[0];
					}
					else
					if (row>i+1) {
						gw=IpAddressUtils.addressPrefix(link3.getPrefix(),1);
						eth_out=eth[3];
					}
					else
					if (column<j) {
						gw=IpAddressUtils.addressPrefix(link1.getPrefix(),3);
						eth_out=eth[1];
					}
					else
					if (column>j) {
						gw=IpAddressUtils.addressPrefix(link2.getPrefix(),2);
						eth_out=eth[2];
					}
					if (gw!=null) rt.add(new Route(dest_prefix,gw,eth_out));			
				}
			}
		}
		return new Network(routers,links);
	}

	
	/** Creates a rectangular topology (Manhattan) with n*m routers, 2(n*m)-n-m core links, and 2(n+m) access links attached to the border routers.
	 * <p>
	 * Access link addresses are assigned starting from the given supernet prefix. Core link addresses are instead taken from different network prefix
	 * ({@link #CORE_LOCAL_LINK_PREFIX4} for IPv4 and {@link #CORE_LOCAL_LINK_PREFIX6} for IPv6).
	 * <p>
	 * The network is composed by IPv4 or Ipv6 routers depending on the type of the prefix address.
	 * @param n the number of rows
	 * @param m the number of columns
	 * @param bit_rate link bit rate
	 * @param loopback_prefix network prefix used for automatically assigning loopback addresses
	 * @param net_prefix network prefix
	 * @return the new network */
	/*public static Network manhattanIpCoreNetwork(int n, int m, long bit_rate, IpPrefix net_prefix) {
		if (n>m) { int x=n; n=m; m=x; } // m>n
		int subnet_len=net_prefix.prefixLength()+IpAddressUtils.ceilLog2(m)+2;
		int subnet_size=1<<(net_prefix.getBytes().length*8-subnet_len);
		IpPrefix core_link_prefix=net_prefix instanceof Ip4Prefix? CORE_LOCAL_LINK_PREFIX4 : CORE_LOCAL_LINK_PREFIX6; // prefix used for core links
		IpLink core_addresses=new IpLink(core_link_prefix); // virtual link used only for assigning unique addresses to all router interfaces

		// Links:
		IpLink[] access_links=new IpLink[2*(m+n)]; // m+m+n+n
		for (int i=0; i<m; i++) access_links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,subnet_len,i));
		for (int i=m; i<2*m; i++) access_links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,subnet_len,subnet_size+i));
		for (int i=2*m; i<2*m+n; i++) access_links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,subnet_len,2*subnet_size+i));
		for (int i=2*m+n; i<2*m+2*n; i++) access_links[i]=new IpLink(bit_rate,IpAddressUtils.subnet(net_prefix,subnet_len,3*subnet_size+i));
		IpLink[] core_links=new IpLink[2*m*n-m-n]; // (m-1)n+(n-1)m
		for (int i=0; i<core_links.length; i++) core_links[i]=new IpLink(bit_rate,core_link_prefix);

		// Routers:		
		Node[] routers=new Node[m*n];
		for (int i=0; i<m; i++) {
			for (int j=0; j<n; j++) {
				IpLink link0=n>0? core_links[i*(2*m+1)+j]; // north
				IpLink link1=links[i*(2*m+1)+m+j]; // west
				IpLink link2=links[i*(2*m+1)+m+j+1]; // east
				IpLink link3=links[i*(2*m+1)+2*m+1+j]; // south
				DataLinkInterface[] eth=new DataLinkInterface[4];
				eth[0]=new DataLinkInterface(link0,IpAddressUtils.addressPrefix(link0.getPrefix(),1)); // north
				eth[1]=new DataLinkInterface(link1,IpAddressUtils.addressPrefix(link1.getPrefix(),2)); // west
				eth[2]=new DataLinkInterface(link2,IpAddressUtils.addressPrefix(link2.getPrefix(),3)); // east
				eth[3]=new DataLinkInterface(link3,IpAddressUtils.addressPrefix(link3.getPrefix(),4)); // south
				//String name="R_"+i+","+j;
				Address loopback_addr=IpAddressUtils.addressPrefix(loopback_prefix,i*m+j+1);
				if (net_prefix instanceof Ip6Prefix) routers[i*m+j]=new Ip6Router(loopback_addr,eth);
				else routers[i*m+j]=new Ip4Router(loopback_addr,eth);
				RoutingTable rt=(RoutingTable)routers[i*m+j].getRouting();
				rt.add(new Route(link0.getPrefix(),null,eth[0]));
				rt.add(new Route(link1.getPrefix(),null,eth[1]));
				rt.add(new Route(link2.getPrefix(),null,eth[2]));
				rt.add(new Route(link3.getPrefix(),null,eth[3]));
				for (int k=0; k<num_of_links; k++) {
					IpPrefix dest_prefix=links[k].getPrefix();
					IpAddress gw=null;
					DataLinkInterface eth_out=null;
					int row=k/(m+n+1);
					int column=(k-row*(n+m+1));
					if (column>=m) column-=m;
					if (row<i) {
						gw=IpAddressUtils.addressPrefix(link0.getPrefix(),4);
						eth_out=eth[0];
					}
					else
					if (row>i+1) {
						gw=IpAddressUtils.addressPrefix(link3.getPrefix(),1);
						eth_out=eth[3];
					}
					else
					if (column<j) {
						gw=IpAddressUtils.addressPrefix(link1.getPrefix(),3);
						eth_out=eth[1];
					}
					else
					if (column>j) {
						gw=IpAddressUtils.addressPrefix(link2.getPrefix(),2);
						eth_out=eth[2];
					}
					if (gw!=null) rt.add(new Route(dest_prefix,gw,eth_out));			
				}
			}
		}
		return new Network(routers,access_links,core_links);
	}*/
	

	/** Creates a binary tree topology with (m^n)-1 routers and (m^(n+1))-2 links, where n is the tree height and m is the tree degree.
	 * Access networks are attached to the tree leaf routers: one access network for each leaf router.
	 * <p>
	 * The network is composed by IPv4 or Ipv6 routers depending on the type of the prefix address.
	 * <p>
	 * The network prefix is used to assign addresses to access networks only.
	 * Core links and core routers use a different network prefix ({@link #CORE_LOCAL_LINK_PREFIX4} for IPv4 and {@link #CORE_LOCAL_LINK_PREFIX6} for IPv6).
	 * In particular, all core links use the same prefix, while the router addresses are assigned as globally unique from that prefix.
	 * Each router has m+1 addresses (m is the degree of the tree).
	 * @param net_prefix network prefix
	 * @param height the tree height (i.e. the number of tree levels)
	 * @param degree the tree degree
	 * @param bit_rate link bit rate
	 * @return the new network */
	public static Network treeIpCoreNetwork(int degree, int height, long bit_rate, IpPrefix net_prefix) {
		List<Node> all_routers=new ArrayList<Node>();
		List<IpLink> access_links=new ArrayList<IpLink>();
		List<IpLink> core_links=new ArrayList<IpLink>();
		IpPrefix core_link_prefix=net_prefix instanceof Ip4Prefix? CORE_LOCAL_LINK_PREFIX4 : CORE_LOCAL_LINK_PREFIX6; // prefix used for core links
		IpLink core_addresses=new IpLink(core_link_prefix); // virtual link used only for assigning unique addresses to all router interfaces
		
		IpLink root_link=new IpLink(core_link_prefix); // upper link toward the root (unused for the root)
		IpAddress root_addr=core_addresses.nextAddressPrefix(); // neighbor on the root link (unused for the root)
		IpAddress node_addr=core_addresses.nextAddressPrefix();	// address on the root link (unused for the root)
		createSubTree(all_routers,access_links,core_links,core_addresses,root_addr,root_link,node_addr,net_prefix,height,degree,bit_rate);
		return new Network(all_routers.toArray(new Node[]{}),access_links.toArray(new IpLink[]{}),core_links.toArray(new IpLink[]{}));
	}
			
	private static void createSubTree(List<Node> all_routers, List<IpLink> access_links, List<IpLink> core_links, IpLink core_addresses, IpAddress root_addr, IpLink root_link, IpAddress node_addr, IpPrefix net_prefix, int more_layers, int degree, long bit_rate) {
		int subnet_bits=IpAddressUtils.ceilLog2(degree);
		//if (degree!=(1<<subnet_bits))throw new RuntimeException("Tree degree must be a power of 2 ("+degree+")");
		
		int num_leaves=more_layers>0? degree : 1;
		IpPrefix[] subnet_prefixes=new IpPrefix[num_leaves];
		IpAddress[] leaf_addrs=new IpAddress[num_leaves];
		IpLink[] subnet_links=new IpLink[num_leaves];
		DataLinkInterface[] link_interfaces=new DataLinkInterface[num_leaves];
		if (more_layers>0) {
			for (int i=0; i<num_leaves; i++) {
				subnet_prefixes[i]=IpAddressUtils.subnet(net_prefix,net_prefix.prefixLength()+subnet_bits,i);
				subnet_links[i]=new IpLink(bit_rate,core_addresses.getPrefix());
				IpAddress addr_i=core_addresses.nextAddressPrefix();
				leaf_addrs[i]=core_addresses.nextAddressPrefix();
				link_interfaces[i]=new IpLinkInterface(subnet_links[i],addr_i);
				core_links.add(subnet_links[i]);
				createSubTree(all_routers,access_links,core_links,core_addresses,addr_i,subnet_links[i],leaf_addrs[i],subnet_prefixes[i],more_layers-1,degree,bit_rate);
			}
		}
		else {
			// leaf routers have one subnet 
			subnet_prefixes[0]=net_prefix;
			subnet_links[0]=new IpLink(bit_rate,subnet_prefixes[0]);
			leaf_addrs[0]=null;
			link_interfaces[0]=new IpLinkInterface(subnet_links[0]);	
			access_links.add(subnet_links[0]);
		}
		Node router=net_prefix instanceof Ip6Prefix? new Ip6Router(node_addr,link_interfaces) : new Ip4Router(node_addr,link_interfaces);
		IpLinkInterface root_interface=new IpLinkInterface(root_link,node_addr);
		router.addNetInterface(root_interface);
		RoutingTable rt=(RoutingTable)router.getRoutingFunction();
		for (int i=0; i<num_leaves; i++) {
			rt.add(new Route(subnet_prefixes[i],leaf_addrs[i],link_interfaces[i]));
		}
		IpPrefix any=net_prefix instanceof Ip6Prefix? Ip6Prefix.ANY : Ip4Prefix.ANY;
		rt.add(new Route(any,root_addr,root_interface));
		all_routers.add(router);
		if (more_layers==0) {
			for (int i=0; i<num_leaves; i++) subnet_links[i].addRouter((IpAddress)link_interfaces[i].getAddresses()[0]);
		}
	}

}
