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


/** A byte buffer with random access input (write) and sequential output (read) operations.
 * <p>
 * The buffer maintains an ordered sequence of bytes starting from a given index;
 * bytes are read (and removed from the buffer) according to this order.
 * <p>
 * On the other hand, bytes can be written in {@link Chunk chunks} in any position of the buffer.
 * If a new {@link Chunk chunk} is overlapped onto an already present chunk, or
 * it only partially exceeds the position of the first byte of the buffer,
 * only the fitting portion of the chunk is added.
 */
public class ChunkBuffer {

	ArrayList<Chunk> buffer=new ArrayList<Chunk>();
	
	long begin;
	
	
	/** Creates a new buffer.
	 * @param begin the sequence number of the first byte (head-of-line) */
	public ChunkBuffer(long begin) {
		this.begin=begin;
	}
	
	/** Creates a new buffer. */
	public ChunkBuffer() {
		begin=0;
	}
	
	/*public long length() {
		if (buffer.size()>0) return end()-begin;
		else return 0;
	}*/

	/** Gets the sequence number of the first byte (head-of-line).
	 * @return the sequence number */
	public long begin() {
		return begin;
	}

	/** Gets the sequence number of the last byte of the last chunk plus one.
	 * @return the sequence number */
	public synchronized long end() {
		if (buffer.size()>0) return buffer.get(buffer.size()-1).end();
		else return begin;
	}

	/** Writes a chunk of data within the buffer.
	 * @param c the chunk to be written */
	public synchronized void write(Chunk c) {
		if (c.end()<=begin) return;
		// else
		if (c.begin()<begin) c=c.subchunk(begin);
		if (buffer.size()==0) {
			buffer.add(c);
			return;
		}
		//else
		for (int i=0; i<buffer.size(); i++) {
			Chunk c_i=buffer.get(i);
			if (c.begin()<c_i.begin()) {
				if (c.end()<=c_i.begin()) {
					buffer.add(i,c);
					return;
				}
				else {
					buffer.add(i,c.subchunk(c.begin(),c_i.begin()));
					if (c.end()>c_i.end()) {
						c=c.subchunk(c_i.end());
						continue;
					}
					else return;
				}
			}
			else
			if (c.begin()<c_i.end() && c.end()>c_i.end()) {
				c=c.subchunk(c_i.end());
				continue;
			}
			else
			if (c.end()<=c_i.end()) return;
		}
		buffer.add(c);
	}

	/** Gets the number of bytes that are currently available in order from the head-of-line.
	 * @return the number of bytes */
	public synchronized int available() {
		if (buffer.size()==0) return 0;
		// else
		int len=0;
		long index=begin;
		for (Chunk c: buffer) {
			if (index>c.begin()) throw new RuntimeException("DEBUG: ChunkBuffer: chunk overlapping: "+toString());
			// else
			if (index==c.begin()) {
				len+=c.length();
				index=c.end();
			}
			else break;
		}
		return len;
	}

	/** Reads all bytes that are currently available in order from the head-of-line. 
	 * @return the bytes */
	public synchronized byte[] read() {
		int len=available();
		byte[] buf=new byte[len];
		if (len>0) read(buf,0);
		return buf;
	}

	/** Reads all bytes that are currently available in order from the head-of-line.
	 * @param buf the buffer were the bytes will be put
	 * @param off the offset within the buffer
	 * @return the number of bytes that has been read */
	public synchronized int read(byte[] buf, int off) {
		if (buffer.size()==0) return 0;
		// else
		int len=0;
		long index=begin;
		while (buffer.size()>0) {
			Chunk c=buffer.get(0);
			if (index>c.begin()) throw new RuntimeException("DEBUG: ChunkBuffer: chunk overlapping: "+toString());
			// else
			if (index==c.begin()) {
				len+=c.getBytes(buf,off+len);
				index=c.end();
				buffer.remove(0);
			}
			else break;
		}
		begin=index;
		return len;
	}
	
	@Override
	public synchronized String toString() {
		//return Arrays.toString(getChunks());
		StringBuffer sb=new StringBuffer();
		for (Chunk c:buffer) {
			sb.append('[').append(c.begin()).append(',').append(c.end()).append(']');
		}
		return sb.toString();
	}

	/** Returns all chunks present within the buffer, without removing them.
	 * @return the chunks */
	public synchronized Chunk[] getChunks() {
		return buffer.toArray(new Chunk[]{});
	}


}
