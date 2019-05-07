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

package it.unipr.netsec.ipstack.tcp;


import org.zoolu.util.Clock;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;


/** A packet and transmission timer.
 */
public class PacketTimer {

	TcpPacket packet;
	int counter=0;
	PacketTimerListener listener;
	Timer timer;
	TimerListener this_timer_listener;
	
	public PacketTimer(TcpPacket packet, PacketTimerListener listener) {
		this.packet=packet;
		this.listener=listener;
		this_timer_listener=new TimerListener() {
			@Override
			public void onTimeout(Timer t) {
				processTimeout(t);
			}			
		};				
	}
	
	public synchronized void start(long retransmission_to) {
		timer=Clock.getDefaultClock().newTimer(retransmission_to,0,this_timer_listener);
		timer.start();	
		counter++;
	}
	
	private void processTimeout(Timer t) {
		if (timer!=null) {
			if (listener!=null) listener.onTimeout(this);
		}
	}			
	
	public void done() {
		if (timer!=null) {
			timer.halt();
			timer=null;
		}
	}

	public TcpPacket getPacket() {
		return packet;
	}

	public int getCounter() {
		return counter;
	}

}
