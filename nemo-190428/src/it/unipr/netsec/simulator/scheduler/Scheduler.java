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



import java.util.SortedSet;
import java.util.TreeSet;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;



/** A scheduler.
 * It schedules and sequentially executes events, here called tasks ({@link SchedulerTask}).
 * Tasks are ordered based on the task attribute ({@link SchedulerTask#time time}). 
 * The attribute <code>time</code> is just used by tasks and scheduler as a virtual time;
 * it doesn't have (and does not need to have) any reference to the real system time.
 */
public class Scheduler {
	
	/** Debug mode */
	public static boolean DEBUG=false;

	/** Prints a debug message. */
	private static void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,Scheduler.class,str);
	}

	
	/** Current time */
	long current_time=0;

	/** Event schedule */
	SortedSet<SchedulerTask> task_schedule=new TreeSet<SchedulerTask>();

	/** Whether a task is running */
	boolean is_running=false;
	
	/** Whether is paused */
	boolean pause=false;

	/** Maximum time */
	long max_time=0;

	
	
	/** Creates a new Scheduler. */
	public Scheduler() {
	}


	/** Gets current time.
	 * @return the current scheduler time corresponding to the last task */
	public long currentTime() {
		return current_time;
	}


	/** Sets maximum time.
	 * Tasks after this time are not scheduled.
	 * @param max_time the maximum time */
	public void setMaximumTime(long max_time) {
		this.max_time=max_time;
	}

	/** Schedules a new task.
	 * @param task the new task
	 * @param delta_time the task relative time from now */
	public void add(SchedulerTask task, long delta_time) {
		task.setTime(current_time+delta_time);
		add(task);
	}


	/** Schedules a new task.
	 * @param task the new task */
	public synchronized void add(SchedulerTask task) {
		if (DEBUG) debug("add("+task+","+task.getTime()+") at "+DateFormat.formatHHmmssSSS(Clock.getDefaultClock().currentTimeMillis()));
		if (max_time==0 || task.getTime()<max_time) {
			int size=task_schedule.size();
			task_schedule.add(task);
			if (task_schedule.size()!=(size+1)) throw new RuntimeException("Scheduler: failed in adding a new task");
			runNext();	
		}
		else {
			if (DEBUG) debug("add(): task time is after the meximim time: discarded");
		}
	}


	/** Runs the next tasks, if any and not already running. */
	private synchronized void runNext() {
		if (!pause && !is_running && hasMore()) {
			is_running=true;
			new Thread() {
				public void run() {
					if (DEBUG) debug("runNext(): new thread "+this); 
					while (!pause && is_running && hasMore()) {
						SchedulerTask task=next();
						if (task!=null) task.action();
					}	
					is_running=false;
					if (DEBUG) debug("runNext(): end of thread "+this); 
				}
			}.start();
		}
	}


	/** Pauses/restarts the scheduler. */
	public void pause(boolean pause) {
		this.pause=pause;
		if (!pause) runNext();
	}

	
	/** Clears all scheduled tasks. */
	public synchronized void clear() {
		task_schedule.clear();
	}

	
	/** Gets the next task.
	 * The scheduler time is moved to the time of this task. The task is removed from the scheduler.
	 * @return the next task, if any; otherwise <i>null</i> is returned */
	private synchronized SchedulerTask next() {
		if (DEBUG) debug("next() at "+DateFormat.formatHHmmssSSS(Clock.getDefaultClock().currentTimeMillis())); 
		if (task_schedule.size()==0) return null;
		// else
		SchedulerTask task=task_schedule.iterator().next();
		task_schedule.remove(task);
		current_time=task.getTime();
		if (DEBUG) debug("next() new current_time: "+DateFormat.formatHHmmssSSS(Clock.getDefaultClock().currentTimeMillis())); 
		return task;
	}


	/** Whether there are some more tasks.
	 * @return <i>true</i> if the are more tasks */
	public synchronized boolean hasMore() {
		return task_schedule.size()>0;
	}
	
}
