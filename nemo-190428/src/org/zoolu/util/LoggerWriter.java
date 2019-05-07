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


import java.io.*;
import java.util.Date;


/** Simple logger that writes log messages onto a logfile, or standard output, or {@link java.io.Writer}, or {@link java.io.OutputStream}
  * or {@link java.io.PrintStream}.
  * <p>
  * When creating a logger you can also specify a <i>priority_level</i> and a <i>maximum_size</i> for the log.
  * <p>
  * The attribute <i>priority_level</i> is used to manage different levels of verboseness.
  * When adding a log message through the method {@link LoggerWriter#log(LoggerLevel, Class, String)}
  * a {@link LoggerLevel} <i>log_level</i> for the given message is specified; only log messages with a <i>log_level</i>
  * greater or equal to the logger <i>priority_level</i> are recorded.
  * <br>
  * With priority level {@link LoggerLevel#OFF} no messages are logged.
  * With priority level {@link LoggerLevel#ALL} all messages are logged.
  * <p>
  * The attribute <i>maximum_size</i> is used to limit the size the log.
  * When the log size reaches the <i>maximum_size</i> value, no more log messages are recorded.
  */
public class LoggerWriter implements Logger {
	
	/** Default maximum log file size (1MB) */
	public static long DEFAULT_MAX_SIZE=1024*1024; // 1MB


	/** The log writer */
	protected Writer out;

	/** The <i>logging_level</i>.
	  * Only messages with a level greater than or equal to this <i>logging_level</i> are logged. */
	LoggerLevel logging_level;
	
	/** The maximum size of the log stream/file [bytes]
	  * Value 0 (or negative) indicates no maximum size */
	long max_size;
	  
	/** Whether writing a timestamp header */
	boolean timestamp=true;

	/** The char counter of the already logged data */
	long counter;



	/** Creates a new LoggerWriter.
	  * @param out the Writer where log messages are written to */
	public LoggerWriter(Writer out) {
		init(out,LoggerLevel.INFO,0);
	}


	/** Creates a new LoggerWriter.
	  * @param out the Writer where log messages are written to 
	  * @param logging_level the logging level */
	public LoggerWriter(Writer out, LoggerLevel logging_level) {
		init(out,logging_level,0);
	}


	/** Creates a new LoggerWriter.
	  * @param out the OutputStream where log messages are written to */
	public LoggerWriter(OutputStream out) {
		init(new OutputStreamWriter(out),LoggerLevel.INFO,0);
	}


	/** Creates a new LoggerWriter.
	  * @param out the OutputStream where log messages are written to
	  * @param logging_level the logging level */
	public LoggerWriter(OutputStream out, LoggerLevel logging_level) {
		init(new OutputStreamWriter(out),logging_level,0);
	}


	/** Creates a new the LoggerWriter.
	  * @param file_name the file where log messages are written to */
	public LoggerWriter(String file_name) {
		init(file_name,LoggerLevel.INFO,DEFAULT_MAX_SIZE,false);
	}


	/** Creates a new the LoggerWriter.
	  * @param file_name the file where log messages are written to
	  * @param logging_level the logging level */
	public LoggerWriter(String file_name, LoggerLevel logging_level) {
		init(file_name,logging_level,DEFAULT_MAX_SIZE,false);
	}


	/** Creates a new the LoggerWriter.
	  * @param file_name the file where log messages are written to
	  * @param logging_level the logging level
	  * @param max_size the maximum size for the log file, that is the maximum number of characters that can be wirtten */
	public LoggerWriter(String file_name, LoggerLevel logging_level, long max_size) {
		init(file_name,logging_level,max_size,false);
	}


	/** Creates a new the LoggerWriter.
	  * @param file_name the file where log messages are written to
	  * @param logging_level the logging level
	  * @param max_size the maximum size for the log file, that is the maximum number of characters that can be wirtten
	  * @param append if <i>true</i>, the file is opened in 'append' mode, that is the new messages are appended to the previously saved file (the file is not rewritten) */
	public LoggerWriter(String file_name, LoggerLevel logging_level, long max_size, boolean append) {
		init(file_name,logging_level,max_size,append);
	}


	/** Initializes the LoggerWriter.
	  * @param out the Writer where log messages are written to
	  * @param logging_level the logging level
	  * @param max_size the maximum size for the log, that is the maximum number of characters that can be written */
	private void init(Writer out, LoggerLevel logging_level, long max_size)  {
		this.out=out;
		this.logging_level=logging_level;
		this.max_size=max_size;
		counter=0;
	}


	/** Initializes the LoggerWriter.
	  * @param file_name the file where log messages are written to
	  * @param logging_level the logging level
	  * @param max_size the maximum size for the log file, that is the maximum number of characters that can be wirtten
	  * @param append if <i>true</i>, the file is opened in 'append' mode, that is the new messages are appended to the previously saved file (the file is not rewritten) */
	private void init(String file_name, LoggerLevel logging_level, long max_size, boolean append) {
		if (logging_level!=LoggerLevel.OFF) {
			try {
				Writer out=new OutputStreamWriter(new FileOutputStream(file_name,append));
				init(out,logging_level,max_size);
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
		else init(null,LoggerLevel.OFF,0);
	}


	/** Sets the logging level.
	  * @param logging_level the logging level */
	/*public void setLevel(LoggerLevel logging_level)  {
		this.logging_level=logging_level;
	}*/


	/** Gets the current logging level.
	  * @return the logging level */
	/*public LoggerLevel getLevel()  {
		return logging_level;
	}*/


	/** Enables or disables writing a timestamp header.
	  * @param timestamp true for including timestamps */
	public void setTimestamp(boolean timestamp)  {
		this.timestamp=timestamp;
	}


	/** Closes the log writer. */
	public void close() {
		if (out!=null) try {  out.close();  } catch (IOException e) {  e.printStackTrace();  }
		out=null;
	}


	/** Adds a log message.
	  * @param level the log level of this message; only messages with log level greater than or equal to the <i>logging_level</i> of the log writer are actually recorded
	  * @param source_class the origin of this log message
	  * @param message the message to be logged */
	@Override
	public synchronized void log(LoggerLevel level, Class source_class, String message) {
		if (level==null) level=LoggerLevel.INFO;
		if (out!=null && level.getValue()>=logging_level.getValue() && (max_size<=0 || counter<max_size)) {
			StringBuffer sb=new StringBuffer();
			if (timestamp) sb.append(DateFormat.formatHHmmssSSS(new Date(System.currentTimeMillis()))).append(": ");
			if (level!=LoggerLevel.INFO) sb.append(level.getName()).append(": ");
			//if (source_class!=null) sb.append(source_class.getSimpleName()).append(": ");
			if (source_class!=null) sb.append(SystemUtils.getSimpleClassName(source_class)).append(": ");
			message=sb.append(message).append("\r\n").toString();
			write(message);
			counter+=message.length();
			if (max_size>0 && counter>=max_size) write("\r\n----MAXIMUM LOG SIZE----\r\nSuccessive logs are lost.");
		}
	}


	/** Writes a string onto the inner writer.
	  * @param str the string to be written */
	protected synchronized void write(String str) {
		try {
			out.write(str);
			out.flush();
		}
		catch (Exception e) {}
	}


	/** Resets the char counter. */
	protected void reset() {
		counter=0;
	}

}
