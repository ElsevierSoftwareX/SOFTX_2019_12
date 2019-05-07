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



import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;



/** Timer that refers to a virtual time according to a given scheduler.
 * <p>
 * The scheduler is supposed to work in nanoseconds.
 */
public class VirtualTimer extends Timer {
	
	/** Scheduler */
	Scheduler scheduler;

	/** Start time */
	long start_time=0;



	/** Creates a new timer.
	 * The timer is not automatically started. You need to call the {@link #start()} method.
	 * @param scheduler the scheduler used as clock for this timer
	  * @param millisecs expiration time in milliseconds
	  * @param nanosecs 0-999999 additional nanoseconds before the timer expires
	 * @param listener timer listener */
	public VirtualTimer(Scheduler scheduler, long millisecs, int nanosecs, TimerListener listener) {
		super(millisecs,nanosecs,listener);
		this.scheduler=scheduler;
	}

	
	@Override
	public long getExpirationTimeNanosecs() {
		if (is_running) {
			long expire=start_time+time_nanosecs-scheduler.currentTime();
			return (expire>0)? expire : 0;
		}
		else return time_nanosecs;
	}

	
	/** Starts the timer. */
	@Override
	public synchronized void start() {
		if (time_nanosecs<0) return;
		// else
		start_time=scheduler.currentTime();
		is_running=true;
		SchedulerTask task=new SchedulerTask() {
			public void action() { timeout(); }
		};
		scheduler.add(task,time_nanosecs);
	}

	
	/** When the timer expires. */
	private synchronized void timeout() {
		if (is_running && listener!=null) listener.onTimeout(this);
		is_running=false;
		listener=null;
	}

}
