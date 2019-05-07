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




/** Log level.
 */
public class LoggerLevel {
	
	/** Level SEVERE (value 100), for very high priority logs (e.g. errors). */
	public static final LoggerLevel SEVERE=new LoggerLevel("SEVERE",100);

	/** Level WARNING (value 80), for high priority logs. */
	public static final LoggerLevel WARNING=new LoggerLevel("WARNING",80);

	/** Level INFO (value 60), for medium priority logs. */
	public static final LoggerLevel INFO=new LoggerLevel("INFO",60);  

	/** Level DEBUG (value 40), for low priority logs. */
	public static final LoggerLevel DEBUG=new LoggerLevel("DEBUG",40); 

	/** Level DEBUG (value 20), for very low priority logs. */
	public static final LoggerLevel TRACE=new LoggerLevel("TRACE",20); 

	/** Priority level OFF, for no logs. */
	public static final LoggerLevel OFF=new LoggerLevel("OFF",Integer.MAX_VALUE); 

	/** Priority level ALL, for all logs. */
	public static final LoggerLevel ALL=new LoggerLevel("ALL",Integer.MIN_VALUE); 

	
	/** Level name */
	String name;
	
	/** Level value */
	int value;

	
	/** Creates a new level.
	 * @param name the level name
	 * @param value the level value */
	public LoggerLevel(String name, int value) {
		this.name=name;
		this.value=value;
	}

	/** Whether this object equals to an other object.
	 * @param obj the other object that is compared to
	 * @return true if the object is a LoggerLevel and the two level values are equal */
	public boolean equals(Object obj) {
		if (this==obj) return true;
		// else
		if (obj!=null && obj instanceof LoggerLevel) return value==((LoggerLevel)obj).getValue();
		// else
		return false;
	}

	/** Gets the level value.
	 * @return the level value */
	public int getValue() {
		return value;
	}

	/** Gets the level name.
	 * @return the level name */
	public String getName() {
		return name;
	}

	/** Gets a string representation of this object.
	 * @return the level name */
	public String toString() {
		return name;
	}

}
