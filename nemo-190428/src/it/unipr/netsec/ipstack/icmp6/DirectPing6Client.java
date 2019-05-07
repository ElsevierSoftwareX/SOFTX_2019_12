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


import java.io.PrintStream;

import org.zoolu.util.Clock;

import it.unipr.netsec.ipstack.icmp4.IcmpLayer;
import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoReplyMessage;
import it.unipr.netsec.ipstack.icmp6.message.Icmp6EchoRequestMessage;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Layer;
import it.unipr.netsec.ipstack.ip6.Ip6LayerListener;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;


/** PING client.
 * It sends ICMP Echo Request messages to a remote node and captures possible
 * ICMP Echo Reply messages.
 * <p>
 *  it is implemented directly on top of the {@link it.unipr.netsec.ipstack.ip4.Ip4Layer}
 *  without getting the {@link IcmpLayer} from the Ip4Layer.
 */
public class DirectPing6Client {
	
	/** Counter of received replies */
	int reply_count=0;

	/** Last received packet time */
	long last_time=-1;

	
	/** Creates a run a ping session.
	 * @param ip_layer IP layer
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param out output where ping results are printed */
	public DirectPing6Client(Ip6Layer ip_layer, final Ip6Address target_ip_addr, int count, final PrintStream out) {
		this(ip_layer,0,"01234567890123456789".getBytes(),target_ip_addr,count,1000,out);		
	}

	/** Creates a run a ping session.
	 * @param ip_layer IP layer
	 * @param echo_id identifier in the ICMP Echo request
	 * @param echo_data payload data in the ICMP Echo request
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param ping_time ping period time
	 * @param out output where ping results are printed */
	public DirectPing6Client(Ip6Layer ip_layer, final int echo_id, final byte[] echo_data, final Ip6Address target_ip_addr, int count, final long ping_time, final PrintStream out) {
		out.println("PING6 "+target_ip_addr+" "+echo_data.length+" bytes of data:");
		final long start_time=Clock.getDefaultClock().currentTimeMillis();
		Ip6LayerListener this_ip_listener=new Ip6LayerListener() {
			@Override
			public void onReceivedPacket(Ip6Layer ip_layer, Ip6Packet ip_pkt) {
				Icmp6Message icmp_msg=new Icmp6Message(ip_pkt);
				//SystemUtils.log(LoggerLevel.DEBUG,"PingClinet: ICMP message ("+icmp_msg.getType()+") received from "+icmp_msg.getSourceAddress()+" (target="+target_ip_addr+")");
				if (icmp_msg.getSourceAddress().equals(target_ip_addr) && icmp_msg.getType()==Icmp6Message.TYPE_Echo_Reply) {
					Icmp6EchoReplyMessage icmp_echo_reply=new Icmp6EchoReplyMessage(icmp_msg);
					//SystemUtils.log(LoggerLevel.DEBUG,"PingClinet: ICMP Echo Reply message: id: "+icmp_echo_reply.getIdentifier()+" ("+echo_id+")");
					if (icmp_echo_reply.getIdentifier()==echo_id) {
						int sqn=icmp_echo_reply.getSequenceNumber();
						last_time=Clock.getDefaultClock().currentTimeMillis()-start_time;
						long time=last_time-ping_time*sqn;
						out.println(""+icmp_echo_reply.getEchoData().length+" bytes from "+icmp_msg.getSourceAddress()+": icmp_sqn="+icmp_echo_reply.getSequenceNumber()+" ttl="+ip_pkt.getHopLimit()+" time="+time+" ms");
						reply_count++;
					}
				}					
			}
		};
		ip_layer.setListener(Ip6Packet.IPPROTO_ICMP6,this_ip_listener);
	
		for (int sqn=0; sqn<count; sqn++) {
			Icmp6EchoRequestMessage icmp_echo_request=new Icmp6EchoRequestMessage(ip_layer.getSourceAddress(target_ip_addr),(Ip6Address)target_ip_addr,echo_id,sqn,echo_data);
			ip_layer.send(icmp_echo_request.toIp6Packet());
			Clock.getDefaultClock().sleep(start_time+(sqn+1)*ping_time-Clock.getDefaultClock().currentTimeMillis());
		}
		// sleep extra time before ending
		Clock.getDefaultClock().sleep(2*ping_time);		
		ip_layer.removeListener(this_ip_listener);
		
		out.println("\n--- "+target_ip_addr+" ping statistics ---");
		if (last_time<0) last_time=Clock.getDefaultClock().currentTimeMillis()-start_time;
		out.println(""+count+" packets transmitted, "+reply_count+" received, "+((count-reply_count)*100/(double)count)+"% packet loss, total time "+last_time+"ms");

	}

}
