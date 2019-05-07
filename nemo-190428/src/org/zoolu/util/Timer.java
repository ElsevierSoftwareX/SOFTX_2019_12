/*
 * Copyright (c) 2018 Luca Veltri, University of Parma
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package org.zoolu.util;


import java.util.TimerTask;


/** A Timer is a simple object that fires the {@link TimerListener#onTimeout(Timer)}
  * method when the time expires.
  * Timer has to be explicitly started, and can be halted before it expires.
  * <p>
  * A timer may run is 'daemon' mode or 'non-daemon' mode.
  * <br>
  * In 'daemon' mode, if all program threads terminate, the timer terminates silently,
  * without firing the corresponding timeout callback.
  * <br>
  * Conversely, in 'non-daemon' mode, the program terminates only when the timer
  * expires (or it is explicitly halted).
  */
public class Timer {
	
	/** Whether the default mode is 'daemon', or not */
	public static boolean DEFAULT_DAEMON_MODE=false;

	/** Maximum number of attempts to schedule the task */
	static final int MAX_ATTEPTS=2;
	
	// Non-daemon scheduled tasks:

	/** Current number of total non-daemon scheduled tasks */
	static int scheduled_tasks=0;

	/** Inner non-daemon scheduler. The program terminates only when all non-daemon timers (associated to this scheduler) have ended (for timeout or explicitly halted) */
	static java.util.Timer scheduler=null;

	/** Lock for the non-daemon scheduler */
	static Object scheduler_lock=new Object();

	// Daemon scheduled tasks:

	/** Inner daemon scheduler. Daemon timers (associated to the this scheduler) silently terminate (without firing the corresponding timeout callbacks) when all program threads end */
	static java.util.Timer daemon_scheduler=null;


	
	/** Whether running in 'daemon' mode */
	boolean daemon_mode;

	/** Start time in time_nanosecs */
	long start_time=0;

	/** Expiration time in time_nanosecs */
	protected long time_nanosecs;

	/** Whether this timer is running */
	protected boolean is_running=false;

	/** Timer listener */
	protected TimerListener listener;
	  

	/** Creates a new timer.
	  * <p>
	  * The timer is not automatically started. You need to call the {@link #start()} method.
	  * @param millisecs expiration time in milliseconds
	  * @param nanosecs 0-999999 additional nanoseconds before the timer expires
	  * @param listener timer listener */
	public Timer(long millisecs, int nanosecs, TimerListener listener) {
		this.listener=listener;
		this.time_nanosecs=millisecs*1000000+nanosecs;
	}  

	
	/** Gets the initial expiration time in milliseconds.
	  * @return the expiration time in milliseconds */
	public long getTimeMillisecs() {
		return time_nanosecs/1000000;
	}

	
	/** Gets the initial expiration time in nanoseconds.
	  * @return the expiration time in nanoseconds */
	public long getTimeNanosecs() {
		return time_nanosecs;
	}

	
	/** Gets the remaining time in milliseconds.
	  * @return the remaining time in milliseconds */
	public long getExpirationTimeMillisecs() {
		return getExpirationTimeNanosecs()/1000000;
	}
	

	/** Gets the remaining time in nanoseconds.
	  * @return the remaining time in nanoseconds */
	public long getExpirationTimeNanosecs() {
		if (is_running) {
			long expire=start_time+time_nanosecs-System.nanoTime();
			return (expire>0)? expire : 0;
		}
		else return time_nanosecs;
	}
	

	/** Starts the timer. */
	public void start() {
		start(DEFAULT_DAEMON_MODE);
	}


	/** Starts the timer.
	 * @param daemon_mode whether running in 'daemon' mode
	 * In 'daemon' mode, when all other threads terminate, the program also ends
	 * regardless the timer was still running, and no timeout callback is fired.
	 * In 'non-daemon' mode, the program ends only when all active timers have expired
	 * or explicitly halted. */
	public synchronized void start(boolean daemon_mode) {
		if (time_nanosecs<0 || is_running) return;
		// else
		this.daemon_mode=daemon_mode;
		start_time=System.nanoTime();
		is_running=true;
		if (time_nanosecs>0) {
			TimerTask task=new TimerTask() {
				public void run() { processInnerTimeout(); }   
			};
			scheduleTask(task,time_nanosecs,daemon_mode);
		}
		else {
			// fire now!			
			processInnerTimeout();  
		}
	}
	
	
	/** Schedule a new task.
	 * @param task the task to be scheduled
	 * @param time_nanosecs the time in nanoseconds
	 * @param daemon_mode whether running in 'daemon' mode */
	private synchronized static void scheduleTask(TimerTask task, long nanosecs, boolean daemon_mode) {
		// FIX: since java.util.Time has only milliseconds precision, do statistical approximation (if nanosecs%1000000!=0)
		long millisecs=nanosecs/1000000;
		long nanoremainder=nanosecs%1000000;
		if (nanoremainder>0 && Random.nextInt(1000000)<nanoremainder) millisecs++;
		
		for (int attempts=0; attempts<MAX_ATTEPTS; attempts++) {
			if (daemon_mode) {
				try  {
					if (daemon_scheduler==null) daemon_scheduler=new java.util.Timer(true); 
					//daemon_scheduler.schedule(task,nanosecs/1000000);
					daemon_scheduler.schedule(task,millisecs);
					break;
				}
				catch (IllegalStateException e) { daemon_scheduler=null; }
			}
			else {
				synchronized (scheduler_lock) {
					try  {
						if (scheduler==null) scheduler=new java.util.Timer(false); 
						//scheduler.schedule(task,nanosecs/1000000);
						scheduler.schedule(task,millisecs);
						scheduled_tasks++;
					    break;						
					}
					catch (IllegalStateException e) { scheduler=null; }	
				}
			}
		}
	}


	/** Whether the timer is running.
	  * @return <i>true</i> if it is running */
	public boolean isRunning() {
		return is_running;
	}   


	/** Stops the Timer.
	  * The method {@link TimerListener#onTimeout(Timer)} of the timer listener will not be fired. */
	public void halt() {
		terminate();
	}

	
	/** When the InnerTimer expires. */
	private synchronized void processInnerTimeout() {
		if (is_running && listener!=null) listener.onTimeout(this);  
		terminate();
	}

	
	/** Terminates the Timer. */
	private synchronized void terminate() {
		if (is_running) {
			is_running=false;
			listener=null;
			if (!daemon_mode && time_nanosecs>0) {
				// the timer has been scheduled in 'non-daemon' mode
				synchronized (scheduler_lock) {
					scheduled_tasks--;
					if (scheduled_tasks==0) {
						scheduler.cancel();
						scheduler.purge();
					}			
				}
			}		
		}
	}
	
}
