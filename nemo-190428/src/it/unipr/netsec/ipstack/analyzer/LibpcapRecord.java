package it.unipr.netsec.ipstack.analyzer;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.DateFormat;

import it.unipr.netsec.ipstack.net.Packet;


/** Libpcap Packet Record.
 * <p>
 * It contains the packet timestamp (seconds and microseconds), the actual packet length, all packet octects or a portion of the packet.
 * <!--<p>
 * @see <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat">wiki.wireshark.org/Development/LibpcapFileFormat</a> for details.
 * -->
 */
public class LibpcapRecord {

	
	/** Timestamp seconds [32bit] */
	long ts_sec=0;
	
	/** Timestamp microseconds [32bit] */
	long ts_usec=0;
	
	/** Number of octets of packet saved in file [32bit] */
	//int incl_len=0;
	
	/** Actual length of packet [32bit] */
	int orig_len=0;
	
	/** Packet data */
	byte[] data=null;

	
	private static byte[] INT32_BUFFER=new byte[4];
	
	private synchronized long readInt32(InputStream is) throws IOException {
		int len=is.read(INT32_BUFFER);
		if (len!=4) throw new IOException("Too few bytes availables ("+len+")");
		return ByteUtils.fourBytesToIntLittleEndian(INT32_BUFFER);
	}

	private synchronized void writeInt32(OutputStream os, long n) throws IOException {
		ByteUtils.intToFourBytesLittleEndian(n,INT32_BUFFER,0);
		os.write(INT32_BUFFER);
	}

	
	/** Creates an empty Libpcap packet record. */
	public LibpcapRecord() {
	}

	/** Creates a new Libpcap record.
	 * @param timestamp the timestamp, in milliseconds
	 * @param pkt the packet */
	/*public LibpcapRecord(long timestamp, Packet pkt) {
		ts_sec=timestamp/1000;
		ts_usec=(timestamp%1000)*1000;
		data=pkt.getBytes();
		orig_len=data.length;
	}*/
	
	/** Creates a new Libpcap record.
	 * @param ts_sec timestamp seconds
	 * @param ts_usec timestamp microseconds
	 * @param pkt the packet */
	public LibpcapRecord(long ts_sec, long ts_usec, Packet pkt) {
		this.ts_sec=ts_sec;
		this.ts_usec=ts_usec;
		data=pkt.getBytes();
		orig_len=data.length;
	}
	
	/** Gets timestamp seconds.
	 * @return the timestamp seconds */
	public long getTimestampSeconds() {
		return ts_sec;
	}
	
	/** Gets timestamp microseconds.
	 * @return the timestamp microseconds */
	public long getTimestampMicroseconds() {
		return ts_usec;
	}
	
	/** Gets timestamp.
	 * @return the timestamp in milliseconds */
	private long getTimestamp() {
		return ts_sec*1000+(ts_usec/1000);
	}
	
	/** Gets packet data.
	 * @return the byte array containing the packet */
	public byte[] getPacketData() {
		return data;
	}
	
	/** Reads the packet record from an InputStream.
	 * @param is the InputStream where the packet record is read from
	 * @return the number of bytes that have been read */
	public synchronized int read(InputStream is) throws IOException {	
		ts_sec=readInt32(is);
		ts_usec=readInt32(is);
		int incl_len=(int)readInt32(is);
		orig_len=(int)readInt32(is);
		data=new byte[incl_len];
		int len=is.read(data);
		if (len!=incl_len) throw new IOException("Too few bytes availables ("+len+"<"+incl_len+")");
		return 16+len;
	}
	
	/** Writes the packet record to an OutputStream.
	 * @param os the OutputStream where the packet record is written to
	 * @return the number of bytes that have been written */
	public int write(OutputStream os) throws IOException {	
		writeInt32(os,ts_sec);
		writeInt32(os,ts_usec);
		writeInt32(os,data.length);
		writeInt32(os,orig_len);
		os.write(data);
		return 16+data.length;
	}

	@Override
	public String toString() {	
		StringBuffer sb=new StringBuffer();
		//sb.append("ts_sec: "+ts_sec+"\n");
		//sb.append("ts_usec: "+ts_usec+"\n");
		//sb.append("incl_len: "+incl_len+"\n");
		//sb.append("orig_len: "+orig_len+"\n");
		sb.append(DateFormat.formatHHmmssSSS(getTimestamp())).append(" ").append("len="+data.length+"/"+orig_len);
		return sb.toString();
	}
}
