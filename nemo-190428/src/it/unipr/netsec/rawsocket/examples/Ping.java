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

package it.unipr.netsec.rawsocket.examples;


import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.icmp4.IcmpLayer;
import it.unipr.netsec.ipstack.icmp4.IcmpLayerListener;
import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoReplyMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoRequestMessage;
import it.unipr.netsec.ipstack.icmp6.Icmp6Layer;
import it.unipr.netsec.ipstack.icmp6.Icmp6LayerListener;
import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoReplyMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoRequestMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4EthInterface;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6AddressPrefix;
import it.unipr.netsec.ipstack.ip6.Ip6EthInterface;
import it.unipr.netsec.ipstack.ip6.Ip6Layer;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.rawsocket.ethernet.RawEthInterface;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.Random;

import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** PING client.
 * It sends ICMP Echo Request messages to a remote node and captures possible
 * ICMP Echo Reply messages.
 * <p>
 * It uses {@link it.unipr.netsec.rawsocket.ethernet.RawEthInterface} for sending
 * and capturing ICMP over IP over Ethernet packets.
  */
public class Ping {
	

	/** Creates a run a ping4 session.
	 * @param ip_layer IPv4 layer
	 * @param echo_id identifier in the ICMP Echo request
	 * @param echo_data payload data in the ICMP Echo request
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param ping_time ping period time */
	public Ping(Ip4Layer ip_layer, final int echo_id, final byte[] echo_data, final Ip4Address target_ip_addr, int count, long ping_time) {
		IcmpLayer icmp_layer=new IcmpLayer(ip_layer);
		System.out.println("PING "+target_ip_addr+" "+echo_data.length+" bytes of data:");
		IcmpLayerListener this_icmp_listener=new IcmpLayerListener() {
			@Override
			public void onReceivedIcmpMessage(IcmpLayer icmp_layer, Ip4Packet ip_pkt) {
				IcmpMessage icmp_msg=new IcmpMessage(ip_pkt);
				//System.out.println("DEBUG: PingClinet: ICMP message ("+icmp_msg.getType()+") received from "+icmp_msg.getSourceAddress()+" (target="+target_ip_addr+")");
				if (icmp_msg.getSourceAddress().equals(target_ip_addr) && icmp_msg.getType()==IcmpMessage.TYPE_Echo_Reply) {
					IcmpEchoReplyMessage icmp_echo_reply=new IcmpEchoReplyMessage(icmp_msg);
					//System.out.println("DEBUG: PingClinet: ICMP Echo Reply message: id: "+icmp_echo_reply.getIdentifier()+" ("+echo_id+")");
					if (icmp_echo_reply.getIdentifier()==echo_id) {
						System.out.println(""+icmp_echo_reply.getEchoData().length+" bytes from "+target_ip_addr+": icmp_sqn="+icmp_echo_reply.getSequenceNumber()+" ttl="+"???"+" time="+"???"+" ms");
					}
				}					
			}
		};
		icmp_layer.addListener(this_icmp_listener);
	
		for (int sqn=0; sqn<count; sqn++) {
			IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(ip_layer.getSourceAddress(target_ip_addr),target_ip_addr,echo_id,sqn,echo_data);
			icmp_layer.send(icmp_echo_request);
			try { Thread.sleep(ping_time); } catch (Exception e) {}
		}
		// sleep extra time before ending
		try { Thread.sleep(ping_time); } catch (Exception e) {}
		
		icmp_layer.close();
	}
	
	
	/** Creates a run a ping6 session.
	 * @param ip_layer IPv6 layer
	 * @param echo_id identifier in the ICMP Echo request
	 * @param echo_data payload data in the ICMP Echo request
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param ping_time ping period time */
	public Ping(Ip6Layer ip_layer, final int echo_id, final byte[] echo_data, final Ip6Address target_ip_addr, int count, long ping_time) {
		Icmp6Layer icmp_provider=new Icmp6Layer(ip_layer);
		System.out.println("PING6 "+target_ip_addr+" "+echo_data.length+" bytes of data:");
		Icmp6LayerListener this_icmp_listener=new Icmp6LayerListener() {
			@Override
			public void onReceivedIcmpMessage(Icmp6Layer icmp_provider, Ip6Packet ip_pkt) {
				Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
				//System.out.println("DEBUG: PingClinet: ICMP message ("+icmp_msg.getType()+") received from "+icmp_msg.getSourceAddress()+" (target="+target_ip_addr+")");
				if (icmp_msg.getSourceAddress().equals(target_ip_addr) && icmp_msg.getType()==Icmp6Message.TYPE_Echo_Reply) {
					Icmp6EchoReplyMessage icmp_echo_reply=new Icmp6EchoReplyMessage(icmp_msg);
					//System.out.println("DEBUG: PingClinet: ICMP Echo Reply message: id: "+icmp_echo_reply.getIdentifier()+" ("+echo_id+")");
					if (icmp_echo_reply.getIdentifier()==echo_id) {
						System.out.println(""+icmp_echo_reply.getEchoData().length+" bytes from "+target_ip_addr+": icmp_sqn="+icmp_echo_reply.getSequenceNumber()+" ttl="+"???"+" time="+"???"+" ms");
					}
				}					
			}
		};
		icmp_provider.addListener(this_icmp_listener);
	
		for (int sqn=0; sqn<count; sqn++) {
			Icmp6EchoRequestMessage icmp_echo_request=new Icmp6EchoRequestMessage(ip_layer.getSourceAddress(target_ip_addr),(Ip6Address)target_ip_addr,echo_id,sqn,echo_data);
			icmp_provider.send(icmp_echo_request);
			try { Thread.sleep(ping_time); } catch (Exception e) {}
		}
		// sleep extra time befor ending
		try { Thread.sleep(ping_time); } catch (Exception e) {}
		
		icmp_provider.close();
	}

		
		
	/** The main method. 
	 * @throws SocketException */
	public static void main(String[] args) throws SocketException {				

		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this messsage");
		boolean debug=flags.getBoolean("-d","debug mode");
		flags.getBoolean("-4","ICMPv4 (default)");
		boolean ping4=!flags.getBoolean("-6","ICMPv6");
		int count=flags.getInteger("-c","<num>",3,"sends only <num> Echo requests");
		long ping_time=flags.getInteger("-t","<time>",1000,"Echo requests are sent every <time> milliseconds");
		String eaddr=flags.getString("-e","<eth-addr>",null,"local Etherent address");
		String eth_name=flags.getString(null,"<interface>",null,"network interface");
		String ipaddr_prefix=flags.getString(null,"<ipaddr>/<prefix-len>",null,"local IP address and prefix length");
		String target=flags.getString(null,"<target>",null,"remote IP address");		
		
		if (help || target==null) {
			System.out.println(flags.toUsageString(Ping.class.getSimpleName()));
			System.out.println(Flags.TAB1+"where <interface> is any of:");
			for (Enumeration<NetworkInterface> i=NetworkInterface.getNetworkInterfaces(); i.hasMoreElements(); ) {
				NetworkInterface ni=i.nextElement();
				System.out.println(Flags.TAB1+Flags.TAB2+ni.getName()+" - "+ni.getDisplayName());
			}
			System.exit(0);
		}
		if (debug) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
			RawEthInterface.DEBUG=true;
			//ArpInterface.DEBUG=true;
			//ArpClient.DEBUG=true;
			//ArpServer.DEBUG=true;
			//IcmpProvider.DEBUG=true;
			
			//Ip6EthInterface.DEBUG=true;
			//NeighborDiscoveryClient.DEBUG=true;
			//NeighborDiscoveryServer.DEBUG=true;
			
			//Node.DEBUG=true;			
		}
		EthAddress local_eth_addr=eaddr!=null? new EthAddress(eaddr) : null;
		int slash=ipaddr_prefix.indexOf('/');
		String addr_str=ipaddr_prefix.substring(0,slash);
		int prefix_len=Integer.parseInt(ipaddr_prefix.substring(slash+1));  	
		Address local_ip_addr=ping4? new Ip4Address(addr_str) : new Ip6Address(addr_str);
		Address target_ip_addr=ping4? new Ip4Address(target) : new Ip6Address(target);
		
		final int echo_id=new Random().nextInt()&0xffff;
		byte[] echo_data="abcdefghabcdefghabcdefghabcdefgh".getBytes();
		
		try {
			NetworkInterface network_interface=NetworkInterface.getByName(eth_name);
			//if (local_eth_addr==null) local_eth_addr=new EthAddress(network_interface.getHardwareAddress());
			InetAddress inet_addr=null;
			for (Enumeration<InetAddress> i=network_interface.getInetAddresses(); i.hasMoreElements(); ) {
				inet_addr=i.nextElement();
				//System.out.println("DEBUG: inet_addr: "+inet_addr);
				if (inet_addr instanceof java.net.Inet4Address) break;
			}
			//if (local_ip_addr==null) local_ip_addr=new Ip4Address(inet_addr.getAddress());
			RawEthInterface eth_interface=local_eth_addr!=null? new RawEthInterface(eth_name,local_eth_addr) : new RawEthInterface(eth_name);
							
			//System.out.println("DEBUG: local Eth addr: "+local_eth_addr.toString());
			//System.out.println("DEBUG: local IP addr: "+local_ip_addr.toString()+"/"+prefix_len);

			if (ping4) {
				Ip4EthInterface ip_interface=new Ip4EthInterface(eth_interface,new Ip4AddressPrefix(local_ip_addr.getBytes(),0,prefix_len));
				Ip4Layer ip_layer=new Ip4Layer(new NetInterface[]{ip_interface});
				new Ping(ip_layer,echo_id,echo_data,(Ip4Address)target_ip_addr,count,ping_time);
				ip_interface.close();		
			}
			else {
				Ip6EthInterface ip_interface=new Ip6EthInterface(eth_interface,new Ip6AddressPrefix(local_ip_addr.getBytes(),0,prefix_len));
				Ip6Layer ip_layer=new Ip6Layer(new NetInterface[]{ip_interface});
				new Ping(ip_layer,echo_id,echo_data,(Ip6Address)target_ip_addr,count,ping_time);
				ip_interface.close();		
			}
			eth_interface.close();
			System.exit(0);
		}
		catch (Exception e) {
			e.printStackTrace();
		}	

	}

}
