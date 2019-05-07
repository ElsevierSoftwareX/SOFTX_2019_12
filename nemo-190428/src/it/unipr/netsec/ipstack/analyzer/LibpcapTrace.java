package it.unipr.netsec.ipstack.analyzer;


import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.zoolu.util.Clock;

import it.unipr.netsec.ipstack.net.Packet;


/** Libpcap-compatible trace.
 * Packets added to this trace are written to a file using standard libpcap format.
 */
public class LibpcapTrace {

	/** Libpcap output file */
	FileOutputStream out;

	/** start time in milliseconds */
	long start_millisecs=0;

	/** start time in nanoseconds */
	long start_nanosecs=0;

	
	/** Create a new trace.
	 * @param type the interface type (see types in class {@link it.unipr.netsec.ipstack.analyzer.LibpcapHeader LibpcapHeader})
	 * @param file_name the pcap file where packets will be written
	 * @throws IOException */
	public LibpcapTrace(int type, String file_name) throws IOException {
		out=new FileOutputStream(file_name);
		LibpcapHeader ph=new LibpcapHeader(type);
		ph.write(out);
	}

	
	/** Adds a new packet to the trace.
	 * @param pkt the packet to be added */
	public void add(Packet pkt) {
		long t_usecs=((Clock.getDefaultClock().nanoTime()-start_nanosecs)+start_millisecs*1000000)/1000;
		try {
			new LibpcapRecord(t_usecs/1000000,t_usecs%1000000,pkt).write(out);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	/** Stops capturing and closes the file. */
	public synchronized void close() {
		if (out!=null) {
			OutputStream temp=out;
			out=null;
			try { temp.close(); } catch (IOException e) {}
		}
	}
	
}
