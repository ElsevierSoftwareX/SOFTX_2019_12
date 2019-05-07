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

package it.unipr.netsec.simulator.scheduler;



import org.zoolu.util.Clock;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;



/** A virtual clock.
 * It provides methods for getting the current time and for creating timers.
 */
public class VirtualClock extends Clock {
	
	/** Task scheduler that provides also current time */
	Scheduler scheduler;


	/** Creates a new virtual clock. */
	public VirtualClock() {
		scheduler=new Scheduler();
	}

	/** Creates a new virtual clock.
	 * @param max_time maximum time in milliseconds */
	public VirtualClock(long max_time) {
		scheduler=new Scheduler();
		scheduler.setMaximumTime(max_time*1000000);
	}

	/** Creates a new virtual clock.
	 * @param scheduler scheduler for the virtual clock */
	public VirtualClock(Scheduler scheduler) {
		this.scheduler=scheduler;
	}

	/** Pauses/restarts the clock. */
	public void pause(boolean pause) {
		scheduler.pause(pause);
	}
		
	@Override
	public Timer newTimer(long millisecs, int nanosecs, TimerListener listener) {
		return new VirtualTimer(scheduler,millisecs,nanosecs,listener);
	}

	@Override
	public long currentTimeMillis() {
		return scheduler.currentTime()/1000000;
	}

	@Override
	public long nanoTime() {
		return scheduler.currentTime();
	}

	@Override
	public void sleep(long millisecs, int nanosecs) {
		if (millisecs*1000000+nanosecs<=0 || nanosecs<0) return;
		// else
		TimerListener timer_listener=new TimerListener() {
			@Override
			public void onTimeout(Timer t) {
				t.notifyAll();
			}		
		};
		Timer t=newTimer(millisecs,nanosecs,timer_listener);
		t.start();
		synchronized (t) {
			try { t.wait(); } catch (InterruptedException e) {}
		}
		
	}

}
