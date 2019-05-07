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


import java.util.Date;
import java.util.Calendar;


/** Class DateFormat can be used to format Date information.
  * It substantially replaces method format() of class java.text.DateFormat.  
  */
public class DateFormat {
	

	/** Months */
	private static final String[] MONTHS={ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


	/** Days of the week */
	private static final  String[] WEEKDAYS={ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };


	/** Formats a double value removing the floating part if not needed. */
	private static String formatDouble(double val) {
		if (Math.floor(val)==val) return Long.toString((long)val);
		else return Double.toString(val);
	}

	
	/** Formats bit rate in kb/s, Mb/s, or Gb/s. */
	public static String formatBitRate(double rate) {
		if (rate>=1000000000) return formatDouble(rate/1000000000)+"Gb/s";
		if (rate>=1000000) return formatDouble(rate/1000000)+"Mb/s";
		if (rate>=1000) return formatDouble(rate/1000)+"kb/s";
		// else
		return formatDouble(rate)+"b/s";
	}

	
	/** Formats a long integer with possibly k, M, or G notation.
	 * A correct string should contain an integer or float value optionally followed by a 'k' or 'M' or 'G' character.
	 * @return the corresponding long integer */
	public static long parseLongKMG(String str) {
		int i=0;
		char c=' ';
		for (; i<str.length(); i++) {
			c=str.charAt(i);
			if (c<'0' || c>'9') break;
		}
		double val=Double.parseDouble(str.substring(0,i));
		if (i<str.length()) {
			switch (c) {
				case 'k' : val*=1000; break;
				case 'K' : val*=1000; break;
				case 'M' : val*=1000000; break;
				case 'G' : val*=1000000000; break;
				default : throw new RuntimeException("Invalid integer format: "+str);
			}
		}
		return (long)Math.round(val);
	}

	
	/** Gets a proper representation of a time in nanoseconds.
	 * @param nanosecs the time in nanoseconds
	 * @return a string representation with unit 's', 'ms', 'us', or, 'ns' depending on the time value */
	public static String formatNanosecs(double nanosecs) {
		if (nanosecs>=1000000000) return formatDouble(nanosecs/1000000000)+"s";
		if (nanosecs>=1000000) return formatDouble(nanosecs/1000000)+"ms";
		if (nanosecs>=1000) return formatDouble(nanosecs/1000)+"us";
		// else
		return formatDouble(nanosecs)+"ns";
	}

		
	/** Gets a "HH:mm:ss.SSS EEE dd MMM yyyy" representation of a date.
	 * @return the formatted date */
	public static String formatHHmmssSSSEEEddMMMyyyy(Date date) {
		//DateFormat df=new SimpleDateFormat("HH:mm:ss.SSS EEE dd MMM yyyy",Locale.US);
		//return df.format(date);
		/*
		String str=date.toString(); // dow mon dd hh:mm:ss zzz yyyy
		int len=str.length();
		String weekday=str.substring(0,3);
		String month=str.substring(4,7);
		String day=str.substring(8,10);
		String time=str.substring(11,19);
		String millisec=Integer.toString((int)(date.getTime()%1000));
		if (millisec.length()==1) millisec="00"+millisec;
		else if (millisec.length()==2) millisec="0"+millisec;
		String year=str.substring(len-4,len);
		
		return time+"."+millisec+" "+weekday+" "+day+" "+month+" "+year;
		*/
		Calendar cal=Calendar.getInstance();
		cal.setTime(date);
		String weekday=WEEKDAYS[cal.get(Calendar.DAY_OF_WEEK)-1];
		String month=MONTHS[cal.get(Calendar.MONTH)];
		String year=Integer.toString(cal.get(Calendar.YEAR));
		String day=Integer.toString(cal.get(Calendar.DAY_OF_MONTH));
		String hour=Integer.toString(cal.get(Calendar.HOUR_OF_DAY));
		String min=Integer.toString(cal.get(Calendar.MINUTE));
		String sec=Integer.toString(cal.get(Calendar.SECOND));
		String millisec=Integer.toString(cal.get(Calendar.MILLISECOND));
		if (day.length()==1) day="0"+day;
		if (hour.length()==1) hour="0"+hour;
		if (min.length()==1) min="0"+min;
		if (sec.length()==1) sec="0"+sec;
		if (millisec.length()==1) millisec="00"+millisec;
		else if (millisec.length()==2) millisec="0"+millisec;
		
		return hour+":"+min+":"+sec+"."+millisec+" "+weekday+" "+day+" "+month+" "+year;
	}

	
	/** Gets a "HH:mm:ss.SSS" representation of a date.
	 * @param date the date to be formatted
	 * @return the formatted date */
	public static String formatHHmmssSSS(Date date) {
		Calendar cal=Calendar.getInstance();
		cal.setTime(date);
		String hour=Integer.toString(cal.get(Calendar.HOUR_OF_DAY));
		String min=Integer.toString(cal.get(Calendar.MINUTE));
		String sec=Integer.toString(cal.get(Calendar.SECOND));
		String millisec=Integer.toString(cal.get(Calendar.MILLISECOND));
		if (hour.length()==1) hour="0"+hour;
		if (min.length()==1) min="0"+min;
		if (sec.length()==1) sec="0"+sec;
		if (millisec.length()==1) millisec="00"+millisec;
		else if (millisec.length()==2) millisec="0"+millisec;
		
		return hour+":"+min+":"+sec+"."+millisec;
	}


	/** Gets a "HH:mm:ss.SSS" representation of a time.
	 * @param time the time in milliseconds
	 * @return the formatted time */
	public static String formatHHmmssSSS(long time) {
		StringBuffer sb=new StringBuffer();
		long hour=(time/3600000L)%24;
		long min=(time/60000L)%60;
		long sec=(time/1000L)%60;
		long millisec=time%1000;
		if (hour<10) sb.append('0');
		sb.append(hour).append(':');
		if (min<10) sb.append('0');
		sb.append(min).append(':');
		if (sec<10) sb.append('0');
		sb.append(sec).append('.');
		if (millisec<10) sb.append("00"); else if (millisec<100) sb.append('0');
		sb.append(millisec);
		return sb.toString();
	}


	/** Gets a "yyyy MMM dd, HH:mm:ss.SSS" representation of a Date.
	 * @param date the date to be formatted
	 * @return the formatted date */
	public static String formatYyyyMMddHHmmssSSS(Date date) {
		Calendar cal=Calendar.getInstance();
		cal.setTime(date);
		String weekday=WEEKDAYS[cal.get(Calendar.DAY_OF_WEEK)-1];
		//String month=MONTHS[cal.get(Calendar.MONTH)];
		String year=Integer.toString(cal.get(Calendar.YEAR));
		String day=Integer.toString(cal.get(Calendar.DAY_OF_MONTH));
		String hour=Integer.toString(cal.get(Calendar.HOUR_OF_DAY));
		String min=Integer.toString(cal.get(Calendar.MINUTE));
		String sec=Integer.toString(cal.get(Calendar.SECOND));
		String millisec=Integer.toString(cal.get(Calendar.MILLISECOND));
		if (day.length()==1) day="0"+day;
		if (hour.length()==1) hour="0"+hour;
		if (min.length()==1) min="0"+min;
		if (sec.length()==1) sec="0"+sec;
		if (millisec.length()==1) millisec="00"+millisec;
		else if (millisec.length()==2) millisec="0"+millisec;
 
		String month=Integer.toString(cal.get(Calendar.MONTH)+1);
		if (month.length()==1) month="0"+month;
		
		return year+"-"+month+"-"+day+" "+hour+":"+min+":"+sec+"."+millisec;
	}


	/** Gets a "EEE, dd MMM yyyy hh:mm:ss 'GMT'" representation of a date.
	 * @param date the date to be formatted
	 * @return the formatted date */
	public static String formatEEEddMMMyyyyhhmmss(Date date) {
		//DateFormat df=new SimpleDateFormat("EEE, dd MMM yyyy hh:mm:ss 'GMT'",Locale.US);
		//return df.format(date);
		/*
		String str=date.toString(); // dow mon dd hh:mm:ss zzz yyyy
		int len=str.length();
		String weekday=str.substring(0,3);
		String month=str.substring(4,7);
		String day=str.substring(8,10);
		String time=str.substring(11,19);
		String year=str.substring(len-4,len);
		return weekday+", "+day+" "+month+" "+year+" "+time+" GMT";
		*/
		Calendar cal=Calendar.getInstance();
		cal.setTime(date);
		String weekday=WEEKDAYS[cal.get(Calendar.DAY_OF_WEEK)-1];
		String month=MONTHS[cal.get(Calendar.MONTH)];
		String year=Integer.toString(cal.get(Calendar.YEAR));
		String day=Integer.toString(cal.get(Calendar.DAY_OF_MONTH));
		String hour=Integer.toString(cal.get(Calendar.HOUR_OF_DAY));
		String min=Integer.toString(cal.get(Calendar.MINUTE));
		String sec=Integer.toString(cal.get(Calendar.SECOND));
		if (day.length()==1) day="0"+day;
		if (hour.length()==1) hour="0"+hour;
		if (min.length()==1) min="0"+min;
		if (sec.length()==1) sec="0"+sec;
		
		return weekday+", "+day+" "+month+" "+year+" "+hour+":"+min+":"+sec+" GMT";
	}


	/** Parses a String for a "EEE, dd MMM yyyy hh:mm:ss 'GMT'" formatted date.
	 * @param str the string containing the formatted time
	 * @param index the position within the string
	 * @return the date */
	public static Date parseEEEddMMMyyyyhhmmss(String str, int index) {
		//DateFormat df=new SimpleDateFormat("EEE, dd MMM yyyy hh:mm:ss 'GMT'",Locale.US);
		//return df.format(date);
		Calendar cal=Calendar.getInstance();
		char[] delim={ ' ', ',', ':' };
		Parser par=new Parser(str,index);
		String EEE=par.getString(); // day of the week
		int day=par.getInt(); // day of the month
		String MMM=par.getString(); // month
		int month=0;
		for (; month<12; month++) if (MMM.equalsIgnoreCase(MONTHS[month])) break;
		if (month==12) return null; // ERROR..
		// else
		int year=par.getInt();
		int hour=Integer.parseInt(par.getWord(delim));
		int min=Integer.parseInt(par.getWord(delim));
		int sec=Integer.parseInt(par.getWord(delim));
		
		cal.set(Calendar.YEAR,year);
		cal.set(Calendar.MONTH,month);
		cal.set(Calendar.DAY_OF_MONTH,day);
		cal.set(Calendar.HOUR_OF_DAY,hour);
		cal.set(Calendar.MINUTE,min);
		cal.set(Calendar.SECOND,sec);

		return cal.getTime();
	}
}
