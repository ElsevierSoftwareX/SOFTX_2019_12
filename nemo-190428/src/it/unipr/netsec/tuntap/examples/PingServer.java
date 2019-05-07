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

package it.unipr.netsec.tuntap.examples;


import it.unipr.netsec.ipstack.arp.ArpPacket;
import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthPacket;
import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoReplyMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoRequestMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.tuntap.TunPacket;
import it.unipr.netsec.tuntap.TuntapSocket;

import java.io.IOException;

import org.zoolu.util.Flags;


/** ICMP server attached to a TUN/TAP interface.
 * <p>
 * It responds to any ICMP Echo request by replying with ICMP Echo reply.
 */
public class PingServer {
	
	/** Default MAC address (in case of TAP interface) */
	private static EthAddress eth_addr=new EthAddress("11:22:33:44:55:66");;

	/** Default IP address */
	private static Ip4Address ip_addr=new Ip4Address("10.1.1.2");

	/** Verbose mode */
	private static boolean VERBOSE=false;

	
	/** Main method. */
	public static void main(String[] args) throws IOException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this message");
		VERBOSE=flags.getBoolean("-v","verbose mode");
		ip_addr=new Ip4Address(flags.getString("-a","<ipaddr>",ip_addr.toString(),"IP address that is resolved by ARP on TAP interface"));
		String tunap_interface=flags.getString(null,"<tuntap>",null,"TUN/TAP interface (e.g. 'tun0')");
		if (help || tunap_interface==null) {
			System.out.println(flags.toUsageString(PingServer.class.getSimpleName()));
			System.exit(0);			
		}
		TuntapSocket.Type type=tunap_interface.toLowerCase().startsWith("tap")? TuntapSocket.Type.TAP : TuntapSocket.Type.TUN;
		
		TuntapSocket tuntap=new TuntapSocket(type,tunap_interface);
		if (VERBOSE) System.out.println(tuntap.getType()+" interface is open");
		
		byte[] rcv_buffer=new byte[8000];
		while (true) {
			int len=tuntap.receive(rcv_buffer,0);
			if (type==TuntapSocket.Type.TUN) {
				// TUN interface
				TunPacket tun_pkt=new TunPacket(rcv_buffer,0,len);
				if (tun_pkt.getPayloadType()==TunPacket.TYPE_IP) {
					Ip4Packet ip_pkt=Ip4Packet.parseIp4Packet(tun_pkt.getPayload());
					ip_pkt=processPingRequest(ip_pkt);
					if (ip_pkt!=null) {
						byte[] data=new TunPacket(ip_pkt).getBytes();
						tuntap.send(data);
					}
				}
			}
			else {
				// TAP interface
				EthPacket eth_pkt=EthPacket.parseEthPacket(rcv_buffer,0,len);
				if (eth_pkt.getType()==EthPacket.ETH_ARP) {
					eth_pkt=processArpRequest(eth_pkt);
					if (eth_pkt!=null) tuntap.send(eth_pkt.getBytes());
				}
				else
				if (eth_pkt.getType()==EthPacket.ETH_IP4) {
					Ip4Packet ip_pkt=Ip4Packet.parseIp4Packet(eth_pkt);
					ip_pkt=processPingRequest(ip_pkt);
					if (ip_pkt!=null) {
						byte[] data=new EthPacket(eth_pkt.getDestAddress(),eth_pkt.getSourceAddress(),EthPacket.ETH_IP4,ip_pkt.getBytes()).getBytes();						
						tuntap.send(data);
					}
				}
			}
		}
	}

	/** If it is a ARP request, returns the ARP reply. */ 
	private static EthPacket processArpRequest(EthPacket eth_pkt) {
		ArpPacket arp_pkt=ArpPacket.parseArpPacket(eth_pkt);
		if (VERBOSE) System.out.println("ARP packet: "+arp_pkt.toString());
		if (arp_pkt.getOperation()==ArpPacket.ARP_REQUEST && new Ip4Address(arp_pkt.getTargetProtocolAddress()).equals(ip_addr)) {
			EthAddress remote_eth_addr=new EthAddress(arp_pkt.getSenderHardwareAddress());
			Ip4Address remote_ip_addr=new Ip4Address(arp_pkt.getSenderProtocolAddress());
			Ip4Address ip_addr=new Ip4Address(arp_pkt.getTargetProtocolAddress());
			ArpPacket arp_reply=new ArpPacket(eth_addr,remote_eth_addr,ArpPacket.ARP_REPLY,eth_addr,ip_addr,remote_eth_addr,remote_ip_addr);
			if (VERBOSE) System.out.println("Sending ARP reply: "+arp_reply.toString());
			return new EthPacket(eth_addr,remote_eth_addr,EthPacket.ETH_ARP,arp_reply.getBytes());
		}		
		return null;
	}

	/** If it is a PING request, returns the PING reply. */ 
	private static Ip4Packet processPingRequest(Ip4Packet ip_pkt) {
		if (ip_pkt.getProto()==Ip4Packet.IPPROTO_ICMP) {
			IcmpMessage icmp_msg=new IcmpMessage(ip_pkt.getSourceAddress(),ip_pkt.getDestAddress(),ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
			if (icmp_msg.getType()==IcmpMessage.TYPE_Echo_Request) {
				IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(icmp_msg);
				if (VERBOSE) System.out.println("Received ICMP Echo request: "+icmp_echo_request);
				// send the Echo reply
				IcmpEchoReplyMessage icmp_echo_reply=new IcmpEchoReplyMessage(icmp_echo_request.getDestAddress(),icmp_echo_request.getSourceAddress(),icmp_echo_request.getIdentifier(),icmp_echo_request.getSequenceNumber(),icmp_echo_request.getEchoData());
				if (VERBOSE) System.out.println("Sending ICMP Echo reply: "+icmp_echo_reply);
				return icmp_echo_reply.toIp4Packet();
			}
			else if (VERBOSE) System.out.println("Received ICMP message: "+icmp_msg);
		}
		else if (VERBOSE) System.out.println("Received IP packet: "+ip_pkt);
		return null;
	}

}
