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


import java.util.Random;


/** A task scheduled at a given time.
 */
public abstract class SchedulerTask implements Comparable<SchedulerTask> {
	
	/** Time */ 
	protected long time=0;

	/** Random generator */ 
	static private Random RAND=null;



	/** Creates a new SchedulerTask.
	 * The scheduled time is 0. */
	public SchedulerTask() {
	}


	/** Creates a new SchedulerTask.
	 * @param time the scheduled time */
	public SchedulerTask(long time) {
		this.time=time;
	}


	/** Sets the scheduled time.
	 * @param time the task time */
	public void setTime(long time) {
		this.time=time;
	}


	/** Gets the scheduled time.
	 * @return the task time */
	public long getTime() {
		return time;
	}


	/** The action associate to this task. */
	public abstract void action();



	/** Task id used by method {@link #compareTo(Object)} in case of identical task time and hash */
	private long id=-1;


	@Override
	public int compareTo(SchedulerTask task) throws ClassCastException {
		// compare the two objects
		if (this==task) return 0;
		// else compare the task time (long)
		long long_diff=time-task.time;
		if (long_diff<0) return -1;
		if (long_diff>0) return 1;
		// else try to compare the object hash value (int)
		int int_diff=hashCode()-task.hashCode();
		if (int_diff!=0) return int_diff;
		// else assign an id to the two tasks
		synchronized (this) {
			if (id==-1) {
				if (RAND==null) RAND=new Random();
				id=RAND.nextLong();
			}
		}
		synchronized (task) {
			if (task.id==-1) {
				if (RAND==null) RAND=new Random();
				task.id=RAND.nextLong();
			}
		}
		long_diff=id-task.id;
		if (long_diff<0) return -1;
		if (long_diff>0) return 1;
		// else
		return 0;
	}
	
}
