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


import org.zoolu.util.ByteUtils;


/** A block of bytes within a longer sequence of bytes.
 * <p>
 * This object is immutable.
 */
public class Chunk {

	private long pos;
	private byte[] buf;
	private int off;
	private int len;
	
	/** Creates an empty chunk.
	 * @param pos the position of the first byte of the chunk */
	protected Chunk(long pos) {
		this.pos=pos;
		this.buf=null;
		this.off=0;
		this.len=0;
	}

	/** Creates a new chunk.
	 * @param pos the position of the first byte of the chunk
	 * @param buf array containing the chunk bytes */
	public Chunk(long pos, byte[] buf) {
		/*this.pos=pos;
		this.buf=buf;
		this.off=0;
		this.len=buf!=null?buf.length:0;*/
		this(pos,buf,0,buf.length);
	}

	/** Creates a new chunk.
	 * @param pos the position of the first byte of the chunk
	 * @param buf buffer containing the bytes
	 * @param off the offset within the buffer
	 * @param len the number of bytes */
	public Chunk(long pos, byte[] buf, int off, int len) {
		/*this.pos=pos;
		this.buf=buf;
		this.off=off;
		this.len=len;*/
		this.pos=pos;
		this.buf=new byte[len];
		this.off=0;
		this.len=len;
		System.arraycopy(buf,off,this.buf,0,len);
	}
	
	/** Returns the position of the first byte of the chunk.
	 * @return the position */
	public long begin() {
		return pos;
	}

	/** Returns the position of the last byte of the chunk plus one.
	 * It is equal to the position of the first byte plus the length of the chunk.
	 * @return the position */
	public long end() {
		return pos+len;
	}

	/** Returns the chunk length. */
	public int length() {
		return len;
	}

	/** Gets the chunk bytes.
	 * @return the array of bytes */
	public byte[] getBytes() {
		//if (buf!=null && off==0 && buf.length==len) return buf;
		// else
		byte[] data=new byte[len];
		if (len>0) System.arraycopy(buf,off,data,0,len);
		return data;
	}

	/** Gets the chunk bytes.
	 * @param buf array where the bytes are written
	 * @param off the offset within the array
	 * @return the number of bytes */
	public int getBytes(byte[] buf, int off) {
		if (len>0) System.arraycopy(this.buf,this.off,buf,off,len);
		return len;
	}
	
	/** Returns a portion of the chunk starting from the given position.
	 * @param begin the starting offset
	 * @return the position */
	public Chunk subchunk(long begin) {
		return subchunk(begin,end());
	}

	/** Gets a portion of the chunk between the two positions.
	 * @param begin the position of the first byte of the portion
	 * @param end the position of the last byte of the portion plus one
	 * @return the new chunk  */
	public Chunk subchunk(long begin, long end) {
		if (begin<pos) throw new RuntimeException("Begin of sub-chunk is out of range ("+begin+"<"+pos+")");
		else
		if (begin>(pos+len)) throw new RuntimeException("Begin of sub-chunk is out of range ("+begin+">"+(pos+len)+")");
		else
		if (end<pos) throw new RuntimeException("End of sub-chunk is out of range ("+end+"<"+pos+")");
		else
		if (end>(pos+len)) throw new RuntimeException("End of sub-chunk is out of range ("+end+">"+(pos+len)+")");
		// else
		//return new Chunk(begin,buf,off+(int)(begin-pos),(int)(end-begin));
		Chunk c=new Chunk(begin);
		c.buf=buf;
		c.off=off+(int)(begin-pos);
		c.len=(int)(end-begin);
		return c;
	}

	@Override
	public String toString() {
		return "{"+pos+",["+ByteUtils.asHex(buf,off,len)+"]}";
	}

}
