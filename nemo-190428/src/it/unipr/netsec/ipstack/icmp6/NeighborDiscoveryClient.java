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

package it.unipr.netsec.ipstack.icmp6;


import org.zoolu.util.Clock;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;

import it.unipr.netsec.ipstack.arp.ArpRecord;
import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6NeighborAdvertisementMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6NeighborSolicitationMessage;
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;
import it.unipr.netsec.ipstack.icmp6.message.option.SourceLinkLayerAddressOption;
import it.unipr.netsec.ipstack.icmp6.message.option.TargetLinkLayerAddressOption;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6EthInterface;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.NetInterfaceListener;
import it.unipr.netsec.ipstack.net.Packet;

import java.util.Enumeration;
import java.util.Hashtable;


/** Neighbor Discovery client.
 * It gets the Ethernet address of a target IPv6 address.
 */
public class NeighborDiscoveryClient {
	
	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	/** Maximum number of attempts */
	public static int MAXIMUM_ATTEMPTS=3;

	/** Retransmission timeout [millisecs] */
	public static long RETRANSMISSION_TIMEOUT=3000;
	
	
	/** IP interface */
	Ip6EthInterface ip_interface;

	/** Local IPv6 address */
	Ip6Address ip_addr;

	/** Local Ethernet address */
	EthAddress eth_addr;

	/** Target Ethernet address */
	EthAddress target_eth_addr;

	/** Target IPv6 address */
	Ip6Address target_ip_addr;

	/** Listener for incoming IP packets */ 
	NetInterfaceListener this_ip_listener;

	/** Retransmission timer */ 
	Timer retransmission_timer=null;

	/** ARP table */
	Hashtable<Ip6Address,ArpRecord> arp_table=null;
	
	/** ARP table timeout in milliseconds, that is the amount of time that a mapping is cached with the local ARP table */
	long arp_table_timeout;


	
	/** Creates a new Neighbor Discovery client.
	 * @param ip_interface the IP interface
	 * @param ip_addr the IP address
	 * @param eth_addr the Ethernet address
	 * @param arp_table_timeout ARP table timeout in milliseconds; if greater than 0, the ARP responses are cached in a local ARP table for this amount of time */
	public NeighborDiscoveryClient(Ip6EthInterface ip_interface, Ip6Address ip_addr, EthAddress eth_addr, long arp_table_timeout) {
		this.ip_interface=ip_interface;
		this.ip_addr=ip_addr;
		this.eth_addr=eth_addr;
		this.arp_table_timeout=arp_table_timeout;
		this_ip_listener=new NetInterfaceListener() {
			@Override
			public void onIncomingPacket(NetInterface ni, Packet pkt) {
				processIncomingPacket(ni,pkt);
			}
		};
		if (arp_table_timeout>0) arp_table=new Hashtable<Ip6Address,ArpRecord>();
	}

	
	/** Gets the Ethernet address of a target IP address.
	 * It sends a ICMP6 Neighbor Solicitation request for the given IP address and captures the Neighbor Advertisement response.
	 * <p>
	 * This is a blocking method. It waits for a response and returns only when a response is received or the maximum number of attempts occurred. 
	 * @param target_ip_addr the target IP address
	 * @return the requested Ethernet address, or <i>null</i> in case of failure */
	public synchronized EthAddress request(Ip6Address target_ip_addr) {
		this.target_ip_addr=target_ip_addr;
		target_eth_addr=null;
		ip_interface.addListener(this_ip_listener);
		try {
			Icmp6Option[] options=new Icmp6Option[]{new SourceLinkLayerAddressOption(eth_addr)};	
			Icmp6NeighborSolicitationMessage ns_msg=new Icmp6NeighborSolicitationMessage(ip_addr,new SolicitedNodeMulticastAddress(target_ip_addr),target_ip_addr,options);
			int remaining_attempts=MAXIMUM_ATTEMPTS;
			TimerListener this_timer_listener=new TimerListener() {
				@Override
				public void onTimeout(Timer t) {
					processTimeout(t);				
				}	
			};
			while (target_eth_addr==null && remaining_attempts>0) {
				ip_interface.send(ns_msg.toIp6Packet(),ns_msg.getDestAddress());
				if (DEBUG) debug("request(): who-has "+target_ip_addr+"? tell "+ip_addr);
				retransmission_timer=Clock.getDefaultClock().newTimer(RETRANSMISSION_TIMEOUT,0,this_timer_listener);
				retransmission_timer.start(true);
				remaining_attempts--;
				// wait for the response
				synchronized (target_ip_addr) {
					if (target_eth_addr==null) try { target_ip_addr.wait(); } catch (InterruptedException e) {}
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		ip_interface.removeListener(this_ip_listener);
		if (DEBUG) debug("request(): response: "+target_eth_addr);
		return target_eth_addr;
	}
	
	
	/** Gets the Ethernet address of a target IP address.
	 * It first looks into a local ARP table; if the address is not found, a ARP request is sent.
	 * @param target_ip_addr the IP address
	 * @return the requested Ethernet address, or <i>null</i> in case of failure */
	public EthAddress lookup(Ip6Address target_ip_addr) {
		if (DEBUG) debug("lookup(): "+target_ip_addr);
		EthAddress eth_addr=null;
		if (DEBUG) {
			StringBuffer sb=new StringBuffer();
			for (Enumeration<Ip6Address> i=arp_table.keys(); i.hasMoreElements(); ) sb.append(i.nextElement()).append(" ");	
			debug("lookup(): ARP table: "+sb.toString());
		}
		if (arp_table!=null && arp_table.containsKey(target_ip_addr)) {
			ArpRecord record=arp_table.get(target_ip_addr);
			if ((record.getTime()+arp_table_timeout)>Clock.getDefaultClock().currentTimeMillis()) {
				eth_addr=record.getAddress();
				if (DEBUG) debug("lookup(): from ARP table: "+eth_addr);
			}
			else arp_table.remove(target_ip_addr);
		}
		if (eth_addr==null) {
			eth_addr=request(target_ip_addr);
			if (DEBUG) debug("lookup(): from network: "+eth_addr);
			if (eth_addr!=null && arp_table!=null && arp_table_timeout>0) arp_table.put(target_ip_addr,new ArpRecord(eth_addr,Clock.getDefaultClock().currentTimeMillis()));
		}
		return eth_addr;
	}

	
	/** Puts the Ethernet address of a given IP address.
	 * @param ip_addr the IP address
	 * @param eth_addr the corresponding Ethernet address */
	public void put(Ip6Address ip_addr, EthAddress eth_addr) {
		if (DEBUG) debug("put(): "+ip_addr+" is-at "+eth_addr);
		arp_table.put(ip_addr,new ArpRecord(eth_addr,Clock.getDefaultClock().currentTimeMillis()));
	}

	
	/** Processes an incoming ARP packet. */
	protected void processIncomingPacket(NetInterface ni, Packet pkt) {
		try {
			Ip6Packet ip_pkt=(Ip6Packet)pkt;
			if (ip_pkt.getPayloadType()==Ip6Packet.IPPROTO_ICMP6) {
				if (DEBUG) debug("processIncomingPacket(): received ICMPv6 packet");
				Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
				int icmp_type=icmp_msg.getType();
				if (icmp_type==Icmp6Message.TYPE_Neighbor_Advertisement) {
					Icmp6NeighborAdvertisementMessage na_msg=new Icmp6NeighborAdvertisementMessage(icmp_msg);
					Ip6Address ip_addr=(Ip6Address)na_msg.getSourceAddress();
					if (ip_addr.equals(target_ip_addr)) {
						Icmp6Option[] options=na_msg.getOptions();
						target_eth_addr=null;
						for (Icmp6Option opt : options) {
							if (DEBUG) debug("processIncomingPacket(): received ICMPv6 Neighbor Advertisement: option: "+opt.getType());
							if (opt.getType()==Icmp6Option.TYPE_Target_Link_Layer_Address) {
								target_eth_addr=new EthAddress(new TargetLinkLayerAddressOption(opt).getLinkLayerAddress().getBytes()); 
							}
						}
						if (DEBUG) debug("processIncomingPacket(): received ICMPv6 Neighbor Advertisement: "+target_ip_addr+" is-at "+target_eth_addr);
						synchronized (target_ip_addr) {
							target_ip_addr.notifyAll();
						}
					}
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	
	/** Processes retransmission timeout. */
	protected void processTimeout(Timer t) {
		synchronized (target_ip_addr) {
			target_ip_addr.notifyAll();
		}
	}

	
	/** Closes the client. */ 
	public void close() {
		ip_interface.removeListener(this_ip_listener);
	}	

}
