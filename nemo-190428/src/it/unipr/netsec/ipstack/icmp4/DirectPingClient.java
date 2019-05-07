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

package it.unipr.netsec.ipstack.icmp4;


import java.io.PrintStream;

import org.zoolu.util.Clock;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;

import it.unipr.netsec.ipstack.icmp4.IcmpMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoReplyMessage;
import it.unipr.netsec.ipstack.icmp4.message.IcmpEchoRequestMessage;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.ip4.Ip4LayerListener;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;


/** PING client.
 * It sends ICMP Echo Request messages to a remote node and captures possible
 * ICMP Echo Reply messages.
 * <p>
 *  it is implemented directly on top of the {@link it.unipr.netsec.ipstack.ip4.Ip4Layer}
 *  without getting the {@link IcmpLayer} from the Ip4Layer.
 */
public class DirectPingClient {
	
	/** Time waited before ending [milliseconds] */
	public static long CLEARING_TIME=3000;

	/** Maximum number of backlogged departures */
	static int BACKLOGGED_DEPARTURES=300; // 5min

	/** IP layer */
	Ip4Layer ip_layer;
	
	/** Identifier in the ICMP Echo request */
	int echo_id;

	/** Payload data in the ICMP Echo request */
	byte[] echo_data;
	
	/** IP address of the target node */
	Ip4Address target_ip_addr;
	
	/** Ping period time */
	long ping_time;
	
	/** Output */
	PrintStream out;

	/** This IP listener */
	Ip4LayerListener this_ip_listener;
	
	/** Starting time */
	long start_time;

	/** Last received packet time */
	long last_time=-1;

	/** Number of ping requests */
	int req_count=0;

	/** Counter of received replies */
	int reply_count=0;
	
	/** Departure times, for computing the RTTs */
	long[] departure_time=new long[BACKLOGGED_DEPARTURES];

	
	/** Creates a runs a ping session.
	 * @param ip_layer IP layer
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param out output where ping results are printed */
	public DirectPingClient(final Ip4Layer ip_layer, final Ip4Address target_ip_addr, int count, final PrintStream out) {
		this(ip_layer,0,"01234567890123456789".getBytes(),target_ip_addr,count,1000,out);
	}

	
	/** Creates a runs a ping session.
	 * @param ip_layer IP layer
	 * @param echo_id identifier in the ICMP Echo request
	 * @param echo_data payload data in the ICMP Echo request
	 * @param target_ip_addr IP address of the target node
	 * @param count the number of ICMP Echo requests to be sent
	 * @param ping_time ping period time
	 * @param out output where ping results are printed */
	public DirectPingClient(final Ip4Layer ip_layer, final int echo_id, byte[] echo_data, final Ip4Address target_ip_addr, int count, final long ping_time, final PrintStream out) {
		this.ip_layer=ip_layer;
		this.echo_id=echo_id;
		this.echo_data=echo_data;
		this.target_ip_addr=target_ip_addr;
		this.ping_time=ping_time;
		this.out=out;
		println("PING "+target_ip_addr+" "+echo_data.length+" bytes of data:");
		start_time=Clock.getDefaultClock().currentTimeMillis();
		this_ip_listener=new Ip4LayerListener() {
			@Override
			public void onReceivedPacket(Ip4Layer ip_layer, Ip4Packet ip_pkt) {
				IcmpMessage icmp_msg=new IcmpMessage(ip_pkt);
				//SystemUtils.log(LoggerLevel.DEBUG,"PingClinet: ICMP message ("+icmp_msg.getType()+") received from "+icmp_msg.getSourceAddress()+" (target="+target_ip_addr+")");
				if (icmp_msg.getSourceAddress().equals(target_ip_addr) && icmp_msg.getType()==IcmpMessage.TYPE_Echo_Reply) {
					IcmpEchoReplyMessage icmp_echo_reply=new IcmpEchoReplyMessage(icmp_msg);
					//SystemUtils.log(LoggerLevel.DEBUG,"Ping: ICMP Echo reply: id="+icmp_echo_reply.getIdentifier()+" sqn="+icmp_echo_reply.getSequenceNumber());
					if (icmp_echo_reply.getIdentifier()==echo_id) {
						int sqn=icmp_echo_reply.getSequenceNumber();
						long now=Clock.getDefaultClock().currentTimeMillis();
						long rtt_time=now-departure_time[sqn%BACKLOGGED_DEPARTURES];
						last_time=now-start_time;
						println(""+icmp_echo_reply.getEchoData().length+" bytes from "+icmp_msg.getSourceAddress()+": icmp_sqn="+icmp_echo_reply.getSequenceNumber()+" ttl="+ip_pkt.getTTL()+" time="+rtt_time+" ms");
						reply_count++;
					}
				}					
			}
		};
		ip_layer.setListener(Ip4Packet.IPPROTO_ICMP,this_ip_listener);
		
		/*for (int sqn=0; sqn<count; sqn++) {
			IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(ip_layer.getSourceAddress(target_ip_addr),target_ip_addr,echo_id,sqn,echo_data);
			SystemUtils.log(LoggerLevel.DEBUG,"Ping: ICMP Echo request at time "+Clock.getDefaultClock().currentTimeMillis()+": id="+icmp_echo_request.getIdentifier()+" sqn="+icmp_echo_request.getSequenceNumber());
			ip_layer.send(icmp_echo_request.toIp4Packet());
			Clock.getDefaultClock().sleep(start_time+(sqn+1)*ping_time-Clock.getDefaultClock().currentTimeMillis());
		}		
		// sleep extra time before ending
		Clock.getDefaultClock().sleep(2*ping_time);
		ip_layer.removeListener(this_ip_listener);
		*/
		ping(0,count);
	}
	
	
	/** Sends a given number of PING requests.
	 * @param sqn starting sequence number
	 * @param count the number of requests to be sent */
	private void ping(final int sqn, final int count) {
		if (count==0) return;
		// else
		IcmpEchoRequestMessage icmp_echo_request=new IcmpEchoRequestMessage(ip_layer.getSourceAddress(target_ip_addr),target_ip_addr,echo_id,sqn,echo_data);
		//SystemUtils.log(LoggerLevel.DEBUG,"Ping: ICMP Echo request at time "+Clock.getDefaultClock().currentTimeMillis()+": id="+icmp_echo_request.getIdentifier()+" sqn="+icmp_echo_request.getSequenceNumber());
		long now=Clock.getDefaultClock().currentTimeMillis();
		departure_time[sqn%BACKLOGGED_DEPARTURES]=now;
		ip_layer.send(icmp_echo_request.toIp4Packet());
		req_count++;
		if (count>1) {
			// sends other PING requests
			TimerListener timer_listener=new TimerListener() {
				@Override
				public void onTimeout(Timer t) {
					ping(sqn+1,count-1);
				}
			};
			//Clock.getDefaultClock().newTimer(ping_time,0,timer_listener).start();
			long next_time=(sqn+1)*ping_time+start_time-now;
			Clock.getDefaultClock().newTimer(next_time,0,timer_listener).start();
		}
		else {
			// wait a while before ending
			TimerListener timer_listener=new TimerListener() {
				@Override
				public void onTimeout(Timer t) {
					ip_layer.removeListener(this_ip_listener);
					println("\n--- "+target_ip_addr+" ping statistics ---");
					if (last_time<0) last_time=Clock.getDefaultClock().currentTimeMillis()-start_time;
					println(""+req_count+" packets transmitted, "+reply_count+" received, "+((req_count-reply_count)*100/(double)req_count)+"% packet loss, total time "+last_time+"ms");
				}
			};
			Clock.getDefaultClock().newTimer(CLEARING_TIME,0,timer_listener).start();
		}
	}
	
	/** Prints out a string.
	 * @param str the string to be printed */
	private void println(String str) {
		if (out!=null) out.println(str);
	}

}
