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

package it.unipr.netsec.ipstack.tcp;


import java.util.ArrayList;


/** A FIFO byte buffer.
 * <p>
 * Bytes are written (added to the buffer) sequentially and
 * they are read (removed from the head of the buffer) according to their input order.
 */
public class StreamBuffer {

	/** Default buffer block size */
	static int DEFAULT_BLOCK_SIZE=512;

	/** Buffer */
	ArrayList<Block> buffer=new ArrayList<Block>();
	
	
	/** Creates a new buffer. */
	public StreamBuffer() {
	}
	
	/*public long length() {
		if (buffer.size()>0) return end()-begin;
		else return 0;
	}*/

	/** Writes a single byte. */
	public void write(byte b) {
		synchronized (buffer) {
			if (buffer.size()>0) {
				Block c=buffer.get(buffer.size()-1);
				if (c.available()>0) {
					c.add(b);
					//buffer.notifyAll();
					return;
				}
			}
			// else
			byte[] buf=new byte[DEFAULT_BLOCK_SIZE];
			buf[0]=b;
			buffer.add(new Block(buf,0,1));
			//buffer.notifyAll();
		}
	}

	/** Writes a block of data within the buffer. */
	public void write(byte[] buf) {
		write(buf,0,buf.length);		
	}

	/** Writes a block of data within the buffer. */
	public void write(byte[] buf, int off, int len) {
		synchronized (buffer) {
			buffer.add(new Block(buf,off,len));
			//buffer.notifyAll();
		}
	}

	/** Returns the number of bytes within the buffer. */
	public synchronized int available() {
		if (buffer.size()==0) return 0;
		// else
		synchronized (buffer) {
			int len=0;
			for (Block c: buffer) len+=c.length();
			return len;
		}
	}

	/** Reads all bytes. */
	/*public byte[] read() {
		synchronized (buffer) {
			int len=available();
			byte[] buf=new byte[len];
			if (len>0) read(buf,0,len);
			return buf;			
		}
	}*/

	/** Reads the first byte. */
	public int read() {
		synchronized (buffer) {
			//while (buffer.size()==0) try { buffer.wait(); } catch (InterruptedException e) {}
			Block c=buffer.get(0);
			byte b=c.head();
			if (c.length()>0) {
				c.remove(1);
			}
			else buffer.remove(0);
			return 0xff&b;
		}		
	}

	/** Reads a block of bytes with with length equal to the minimum between the buffer size and the length of the reader array. */
	public int read(byte[] buf) {
		return read(buf,0,buf.length);
	}
		
	/** Reads a block of bytes with with length equal to the minimum between the buffer size and a specified length. */
	public int read(byte[] buf, int off, int len) {
		synchronized (buffer) {
			//while (buffer.size()==0) try { buffer.wait(); } catch (InterruptedException e) {}
			int count=0;
			for (int i=0; i<buffer.size() && len>0; i++) {
				Block c=buffer.get(i);
				int c_len=c.length();
				if (len>=c_len) {
					c.getBytes(buf,off);
					len-=c_len;
					off+=c_len;
					count+=c_len;
					buffer.remove(i);
					i--;
				}
				else {
					c.getBytes(buf,off,len);
					c.remove(len);
					count+=len;
					len=0;
				}
			}			
			return count;
		}
	}
	
	/** Gets all ytes. */
	public byte[] readAll() {
		synchronized (buffer) {
			byte[] buf=new byte[available()];
			read(buf);
			return buf;
		}
	}

		
	@Override
	public synchronized String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append('[');
		for (int i=0; i<buffer.size(); i++) {
			Block c=buffer.get(i);
			if (i==0) sb.append(c.length());
			else sb.append(',').append(c.length());
		}
		sb.append(']');
		return sb.toString();
	}

}


/** A block of data.
 * It maintains the reference to a portion of a byte array.
 * <p>
 * This object is not immutable since it can be modified by the adding bytes at the end of the block
 * (if enough space is available) or by removing bytes from the head of the block.
 */
class Block {

	private byte[] buf;
	private int off=0;
	private int len=0;
	
	/** Returns the length. */
	public Block(byte[] buf) {
		this(buf,0,buf.length);
	}

	/** Creates a new block of data. */
	public Block(byte[] buf, int off, int len) {
		/*this.buf=buf;
		this.off=off;
		this.len=len;*/
		this.buf=new byte[len];
		this.off=0;
		this.len=len;
		System.arraycopy(buf,off,this.buf,0,len);
	}

	/** Returns the length. */
	public int length() {
		return len;
	}

	/** Gets all bytes. */
	public byte[] getBytes() {
		return getBytes(len);
	}

	/** Gets a specified number of bytes starting from the head.
	 * If not enough bytes are available a {@code RuntimeException} is thrown. */
	public byte[] getBytes(int len) {
		byte[] data=new byte[len];
		getBytes(data,0,len);
		return data;
	}

	/** Gets all bytes.
	 * If the destination is too short a {@code RuntimeException} is thrown. */
	public int getBytes(byte[] buf, int off) {
		return getBytes(buf,off,len);
	}

	/** Gets a specified number of bytes starting from the head.
	 * If not enough bytes are available or the destination is too short a {@code RuntimeException} is thrown. */
	public int getBytes(byte[] buf, int off, int len) {
		if (this.len<len) throw new RuntimeException("Not enough bytes");
		if (buf.length<off+len) throw new RuntimeException("Destination array too small");
		if (len>0) System.arraycopy(this.buf,this.off,buf,off,len);
		return len;
	}

	/** Removes a specified number of bytes from the head.
	 * If not enough bytes are available a {@code RuntimeException} is thrown. */
	public void remove(int num) {
		if (num>len) throw new RuntimeException("Not enough bytes ("+num+")");
		this.off+=num;
		this.len-=num;
	}

	/** Returns the buffer space that is still available at the end of the data. */
	public int available() {
		return buf.length-off-len;
	}

	/** Appends a byte.
	 * If no space is available a {@code RuntimeException} is thrown. */
	public void add(byte b) {
		if (available()==0) throw new RuntimeException("No space is availabe");
		buf[off+len]=b;
		len++;
	}

	/** Returns the first byte (head-of-line). */
	public byte head() {
		if (len==0) throw new RuntimeException("It is empty");
		return buf[off];
	}
}



