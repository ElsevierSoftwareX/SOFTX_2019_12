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


import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;


/** A clock that maintains a time variable.
 * It provides methods for getting the current time and for creating {@link org.zoolu.util.Timer timers}.
 * <p>
 * This class has also a default clock that can be handled through the corresponding
 * two <i>static</i> methods {@link #setDefaultClock(Clock)} and {@link #getDefaultClock()}.
 */
public class Clock {
	
	/** Default clock */
	private static Clock DEFAULT_CLOCK=new Clock();

	/** Sets the default clock.
	 * @param clock the new default clock */
	public static void setDefaultClock(Clock clock)  {
		DEFAULT_CLOCK=clock;
	}

	/** Gets the default clock.
	 * @return the default clock */
	public static Clock getDefaultClock()  {
		return DEFAULT_CLOCK;
	}

	
	/** Creates a new timer.
	  * @param millisecs expiration time in milliseconds
	  * @param nanosecs 0-999999 additional nanoseconds before expires
	  * @param listener timer listener */
	public Timer newTimer(long millisecs, int nanosecs, TimerListener listener) {
		return new Timer(millisecs,nanosecs,listener);
	}
	
	/** Gets current time in milliseconds.
	  * @return the current time in milliseconds */
	public long currentTimeMillis() {
		return System.currentTimeMillis();
	}

	/** Gets time in nanoseconds starting from an unspecified origin.
	 * It can be used for measuring some elapsed time as difference between two instants.
	 * @return the time in nanoseconds */
	public long nanoTime() {
		return System.nanoTime();
	}

	/** Waits for a specified period.
	  * @param millisecs the length of time to sleep in milliseconds */
	public void sleep(long millisecs) {
		sleep(millisecs,0);
	}
	
	/** Waits for a specified period.
	  * @param millisecs the length of time to sleep in milliseconds
	  * @param nanosecs 0-999999 additional nanoseconds to sleep */
	public void sleep(long millisecs, int nanosecs) {
		try { Thread.sleep(millisecs,0); } catch (Exception e) {};
	}


}
