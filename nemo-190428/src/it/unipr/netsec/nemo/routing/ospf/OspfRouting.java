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

package it.unipr.netsec.nemo.routing.ospf;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.nemo.routing.LinkStateInfo;
import it.unipr.netsec.nemo.routing.NetworkMap;
import it.unipr.netsec.nemo.routing.ShortestPathAlgorithm;
import it.unipr.netsec.nemo.routing.DynamicRouting;
import it.unipr.netsec.nemo.routing.DynamicRoutingInterface;
import it.unipr.netsec.nemo.routing.graph.Graph;

import java.util.Arrays;
import java.util.Hashtable;

import org.zoolu.util.Clock;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;


/** Lite implementation of the OSPF protocol.
 * <p>
 * It use Link-State (LS) flooding for distributing OSPF LS updates of all routers and computing the resulting network graph.
 * The routing table is computed from the network graph by applying a SPF (shortest Path First) algorithm.
 * By default, the Dijkstra algorithm is used.
 */
public class OspfRouting implements DynamicRouting {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,OspfRouting.class.getSimpleName()+"["+node_addr+"]: "+str);
	}

	
	/** Start time, when the first LS update is sent, in millisecs */
	public static long START_TIME=500;

	/** LS update retransmission time in millisecs */
	public static long UPDATE_TIME=5000;

	/** RT re-calculation time in millisecs */
	public static long REFRESH_TIME=20000;

	/** LS expiration time in millisecs */
	public static long EXPIRE_TIME=2*UPDATE_TIME;

	
	/** Network map */
	NetworkMap network_map;
	
	/** Node address */
	Ip4Address node_addr;

	/** Interface for dynamic routing configuration */
	DynamicRoutingInterface routing_interface;

	/** LS sequence number */
	long ls_sqn=0;
	
	/** LS advertisements (node address -> OSPF LSA) */
	Hashtable<Ip4Address,RouterLSA> node_to_lsa=new Hashtable<>();
	
	/** Times of the last LSs (node address -> time) */
	Hashtable<Ip4Address,Long> node_to_time=new Hashtable<>();
	
	
	/** Creates a new dynamic routing. */ 
	public OspfRouting() {
		this(ShortestPathAlgorithm.DIJKSTRA);
	}
	
	/** Creates a new dynamic routing.
	 * @param algo shortest-path algorithm */ 
	public OspfRouting(ShortestPathAlgorithm algo) {
		network_map=new NetworkMap(algo);
	}
	
	/** Gets the network graph.
	 * @return the network graph */
	public Graph getNetworkGraph() {
		return network_map.getNetworkGraph();
	}

	@Override
	public void connect(final Address node_addr, final LinkStateInfo[] lsia, DynamicRoutingInterface routing_interface) {
		if (DEBUG) debug("connect(): node="+node_addr+", LS="+Arrays.toString(lsia));
		this.node_addr=(Ip4Address)node_addr;
		this.routing_interface=routing_interface;
		
		// add this node to the graph
		network_map.addLikState(node_addr,lsia);
				
		// periodically send a LS update
		TimerListener send_update_listener=new TimerListener() {
			@Override
			public void onTimeout(Timer t) {
				// generate the LSA
				LSALink[] links=new LSALink[lsia.length];
				for (int i=0; i<links.length; i++) links[i]=new LSALink(LSALink.TYPE_TRANSIT,new Ip4AddressPrefix((Ip4Address)lsia[i].getAddress(),((Ip4Prefix)lsia[i].getPrefix()).prefixLength()),lsia[i].getCost());
				RouterLSA lsa=new RouterLSA(0,0,OspfRouting.this.node_addr,ls_sqn++,links);
				if (DEBUG) debug("onTimeout(): LSA: "+lsa);
				synchronized (node_to_lsa) {
					if (node_to_lsa.containsKey(node_addr)) node_to_lsa.remove(node_addr);
					node_to_lsa.put((Ip4Address)node_addr,lsa);					
				}
				OspfPacket ospf_pkt=new OspfLSUPacket(OspfRouting.this.node_addr,Ip4Address.ADDR_BROADCAST,(Ip4Address)node_addr,Ip4Address.ADDR_UNSPECIFIED,new LSA[]{lsa});
				if (DEBUG) debug("onTimeout(): sending the LS update: "+ospf_pkt);
				sendPacket(ospf_pkt);
				if (UPDATE_TIME>0) Clock.getDefaultClock().newTimer(UPDATE_TIME,0,this).start();
			}
		};
		Clock.getDefaultClock().newTimer(START_TIME,0,send_update_listener).start();

		// periodically refresh the network map
		TimerListener network_refresh_listener=new TimerListener() {
			@Override
			public void onTimeout(Timer t) {
				if (DEBUG) debug("onTimeout(): refresh the network map");
				long now=Clock.getDefaultClock().currentTimeMillis();
				network_map.clear();
				synchronized (node_to_lsa) {
					for (Ip4Address node: node_to_lsa.keySet()) {
						if (node.equals(OspfRouting.this.node_addr) || now-node_to_time.get(node).longValue()<EXPIRE_TIME) {
							network_map.addLikState(node,OspfRouting.getLinkStateInfo(node_to_lsa.get(node)));
						}
						else {
							// collect the node for removing from node_to_lsa and node_to_time after the 'for' loop
							// TODO
						}
					}						
				}
				OspfRouting.this.routing_interface.updateRouting(network_map.getRoutes(OspfRouting.this.node_addr));							
				if (REFRESH_TIME>0) Clock.getDefaultClock().newTimer(REFRESH_TIME,0,this).start();					
			}
		};
		// first refresh
		Clock.getDefaultClock().newTimer(2*START_TIME+UPDATE_TIME,0,network_refresh_listener).start();
	}
		
	private void sendPacket(OspfPacket ospf_pkt) {
		if (DEBUG) debug("sendPacket(): "+ospf_pkt);
		Ip4Packet ip_pkt=ospf_pkt.toIp4Packet();ip_pkt.setTTL(1);
		OspfRouting.this.routing_interface.sendPacket(ip_pkt);
		//OspfRouting.this.routing_interface.sendPacket(ospf_pkt.toIp4Packet());
	}	
	
	@Override
	public void disconnect(Address node_addr) {
		if (this.node_addr==node_addr) {
			this.node_addr=null;
			routing_interface=null;
			network_map.removeLinkState(node_addr);
		}
	}
	
	@Override
	public Packet processReceivedPacket(Address node_addr, Packet pkt) {
		Ip4Packet ip_pkt=(Ip4Packet)pkt;
		if (ip_pkt.getProto()==Ip4Packet.IPPROTO_OSPF) {
			OspfPacket ospf_pkt=new OspfPacket(ip_pkt);
			if (ospf_pkt.getType()==OspfPacket.TYPE_LSU) {
				OspfLSUPacket lsu_pkt=new OspfLSUPacket(ospf_pkt);
				LSA[] lsaa=lsu_pkt.getLSAs();
				for (LSA lsa : lsaa) {
					if (lsa.getType()==LSA.TYPE_Router) {
						RouterLSA rlsa=new RouterLSA(lsa);
						if (DEBUG) debug("processReceivedPacket(): LSA: "+rlsa);
						Ip4Address router=rlsa.getRouter();
						long sqn=rlsa.getSequenceNumber();
						synchronized (node_to_lsa) {
							long prev_sqn=node_to_lsa.containsKey(router)? node_to_lsa.get(router).getSequenceNumber():-1;
							if (sqn>=prev_sqn) node_to_time.put(router,new Long(Clock.getDefaultClock().currentTimeMillis()));
							if (sqn>prev_sqn) {
								if (prev_sqn>=0) node_to_lsa.remove(router);
								node_to_lsa.put(router,rlsa);
								sendPacket(ospf_pkt);
								//network_map.addLikState(router,getLinkStateInfo(rlsa));
								//routing_interface.updateRouting(network_map.getRoutes(node_addr));							
							}							
						}
					}
				}
			}
			return null;
		}
		// else
		return pkt;
	}
	
	/** Extracts LS info from a Router-LSA.
	 * @param rlsa the Router-LSA
	 * @return the LS */
	private static LinkStateInfo[] getLinkStateInfo(RouterLSA rlsa) {
		LSALink[] links=rlsa.getLinks();
		LinkStateInfo[] li=new LinkStateInfo[links.length];
		for (int i=0; i<links.length; i++) {
			Ip4AddressPrefix addr_prefix=links[i].getLinkAddressPrefix();
			li[i]=new LinkStateInfo(addr_prefix,addr_prefix.getPrefix(),links[i].getMetric());
		}
		return li;
	}

}
