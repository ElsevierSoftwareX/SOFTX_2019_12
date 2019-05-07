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
import java.util.Arrays;

import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.ip6.Ip6Packet;
import it.unipr.netsec.ipstack.net.DataPacket;
import it.unipr.netsec.ipstack.tcp.option.EndOfListOption;
import it.unipr.netsec.ipstack.tcp.option.MaximumSegmentSizeOption;
import it.unipr.netsec.ipstack.tcp.option.NoOperationOption;
import it.unipr.netsec.ipstack.tcp.option.Option;
import it.unipr.netsec.ipstack.tcp.option.SackOption;
import it.unipr.netsec.ipstack.tcp.option.SackPermittedOption;
import it.unipr.netsec.ipstack.tcp.option.TimestampsOption;
import it.unipr.netsec.ipstack.tcp.option.TlvOption;
import it.unipr.netsec.ipstack.tcp.option.WindowScaleOption;
import it.unipr.netsec.ipstack.util.Checksum;


/** Transmission Control Protocol (RFC 793) segment unit.
 */
public class TcpPacket extends DataPacket {

	/** Option type End of Option List (len=1) */
	public static final int OPT_END_OF_OPTION_LIST=0;
	/** Option type No-Operation (len=1) */
	public static final int OPT_NO_OPERATION=1;
	/** Option type Maximum Segment Size (len=4) */
	public static final int OPT_MAXIMUM_SEGMENT_SIZE=2;
	/** Option type Window Scale (len=3) */
	public static final int OPT_WINDOW_SCALE=3;
	/** Option type SACK Permitted (len=2) */
	public static final int OPT_SACK_PERMITTED=4;
	/** Option type SACK */
	public static final int OPT_SACK=5;
	/** Option type Timestamps (len=10) */
	public static final int OPT_TIMESTAMPS=8;

	/** Option type Quick-Start Response (len=8) */
	public static final int OPT_QUICK_START_RESPONSE=27;
	/** Option type User Timeout (len=4) */
	public static final int OPT_USER_TIMEOUT=28;
	/** Option type TCP Authentication */
	public static final int OPT_TCP_AO=29;
	/** Option type Multipath TCP */
	public static final int OPT_MPTCP=30;
	/** Option type TCP Fast Open Cookie */
	public static final int OPT_TCP_FAST_COOKIE=34;

	
	/** TCP header offset of src port field */
	private static final int OFFSET_SP=0;
	/** TCP header offset of dest port field */
	private static final int OFFSET_DP=2;
	/** TCP header offset of sequence number field */
	private static final int OFFSET_SQN=4;
	/** TCP header offset of ACK number field */
	private static final int OFFSET_ACK=8;
	/** TCP header offset of HLEN field */
	private static final int OFFSET_HLEN=12;
	/** TCP header offset of flags */
	private static final int OFFSET_FLAGS=12;
	/** TCP header offset of window size field */
	private static final int OFFSET_WIN=14;
	/** TCP header offset of checksum */
	private static final int OFFSET_CSUM=16;
	/** TCP header offset of urgent pointer */
	private static final int OFFSET_URG=18;
	/** TCP header offset of options */
	private static final int OFFSET_OPTIONS=20;
	
	/** TCP flag NS */
	private static final int FLAG_NS=0x0100;
	/** TCP flag CWR */
	private static final int FLAG_CWR=0x0080;
	/** TCP flag ECE */
	private static final int FLAG_ECE=0x0040;
	/** TCP flag URG */
	private static final int FLAG_URG=0x0020;
	/** TCP flag ACK */
	private static final int FLAG_ACK=0x0010;
	/** TCP flag PSH */
	private static final int FLAG_PSH=0x0008;
	/** TCP flag RST */
	private static final int FLAG_RST=0x0004;
	/** TCP flag SYN */
	private static final int FLAG_SYN=0x0002;
	/** TCP flag FIN */
	private static final int FLAG_FIN=0x0001;

	/** Source port */
	int src_port;
	
	/** Destination port */
	int dst_port;

	/** Sequence number */
	long sqn;
	
	/** Acknowledge number */
	long ack=-1;

	/** Urgent pointer */
	int urg=-1;

	/** Window */
	int window=8192;

	/** Synchronize (SYN) flag */
	boolean syn=false;

	/** Finish (FIN) flag */
	boolean fin=false;

	/** Reset (RST) flag */
	boolean rst=false;

	/** Push (PSH) flag */
	boolean psh=false;
	
	/** Segment checksum (0 if it is unspecified) */
	//int checksum=0;

	/** Whether the checksum is correct (1), unspecified (0), wrong (-1) */
	int checksum_check=0;

	/** TCP options */
	Option[] options=null;

	/** Creates a new TCP segment.
	 * @param src_addr source address
	 * @param src_port source port
	 * @param dst_addr destination address
	 * @param dst_port destination port
	 * @param sqn sequence number
	 * @param ack if &ge;0, the ACK number
	 * @param data the packet payload */
	public TcpPacket(IpAddress src_addr, int src_port, IpAddress dst_addr, int dst_port, long sqn, long ack, byte[] data) {
		super(src_addr,dst_addr,data);
		this.src_port=src_port;
		this.dst_port=dst_port;
		this.sqn=sqn;
		if (ack>=0) this.ack=ack;
	}

	
	/** Creates a new TCP segment.
	 * @param src_addr source address
	 * @param src_port source port
	 * @param dst_addr destination address
	 * @param dst_port destination port
	 * @param sqn sequence number
	 * @param ack if &ge;0, the ACK number
	 * @param data_buf the buffer containing the packet payload
	 * @param data_off the offset within the buffer
	 * @param data_len the payload length */
	public TcpPacket(IpAddress src_addr, int src_port, IpAddress dst_addr, int dst_port, long sqn, long ack, byte[] data_buf, int data_off, int data_len) {
		super(src_addr,dst_addr,data_buf,data_off,data_len);
		this.src_port=src_port;
		this.dst_port=dst_port;
		this.sqn=sqn;
		if (ack>=0) this.ack=ack;
	}

	
	/** Parses a TCP segment.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param buf buffer containing the UDP packet
	 * @param off the offset within the buffer
	 * @param len the length of the TCP packet */
	public static TcpPacket parseTcpPacket(IpAddress src_addr, IpAddress dst_addr, byte[] buf, int off, int len) {
		int src_port=ByteUtils.twoBytesToInt(buf,off+OFFSET_SP);
		int dst_port=ByteUtils.twoBytesToInt(buf,off+OFFSET_DP);
		long sqn=ByteUtils.fourBytesToInt(buf,off+OFFSET_SQN);
		long ack=ByteUtils.fourBytesToInt(buf,off+OFFSET_ACK);
		int hlen=((buf[off+OFFSET_HLEN]&0xf0)>>4)*4;
		int flags=((buf[off+OFFSET_FLAGS]&0xff)<<8) + (buf[off+OFFSET_FLAGS+1]&0xff);
		//debug("initTcpHeader(): flags: "+Integer.toString(flags,2));		
		if ((flags&FLAG_ACK)==0) ack=-1;
		boolean rst=(flags&FLAG_RST)!=0;
		boolean syn=(flags&FLAG_SYN)!=0;
		boolean fin=(flags&FLAG_FIN)!=0;
		boolean psh=(flags&FLAG_PSH)!=0;
		int fwin=ByteUtils.twoBytesToInt(buf,off+OFFSET_WIN);
		int urg=ByteUtils.twoBytesToInt(buf,off+OFFSET_URG);
		if ((flags&FLAG_URG)==0) urg=-1;
		
		ArrayList<Option> options=new ArrayList<Option>();
		int index=OFFSET_OPTIONS;
		while (index<hlen) {
			Option opt;
			switch (0xff&buf[off+index]) {
				case OPT_END_OF_OPTION_LIST : opt=new EndOfListOption(); break;
				case OPT_NO_OPERATION : opt=new NoOperationOption(); break;
				case OPT_MAXIMUM_SEGMENT_SIZE : opt=MaximumSegmentSizeOption.parseOption(buf,off+index); break;
				case OPT_WINDOW_SCALE : opt=WindowScaleOption.parseOption(buf,off+index); break;
				case OPT_SACK_PERMITTED : opt=SackPermittedOption.parseOption(buf,off+index); break;
				case OPT_SACK : opt=SackOption.parseOption(buf,off+index); break;
				case OPT_TIMESTAMPS : opt=TimestampsOption.parseOption(buf,off+index); break;
				default : opt=TlvOption.parseTlvOption(buf,off+index); break;
			}
			if (opt.getType()==OPT_END_OF_OPTION_LIST) break;
			// else
			options.add(opt);
			index+=opt.getTotalLength();
		}	
		TcpPacket tcp_pkt=new TcpPacket(src_addr,src_port,dst_addr,dst_port,sqn,ack,buf,off+hlen,len-hlen);
		// set ack, urg, win, etc
		tcp_pkt.setRst(rst);
		tcp_pkt.setSyn(syn);
		tcp_pkt.setFin(fin);
		tcp_pkt.setPsh(psh);
		tcp_pkt.setWindow(fwin);
		tcp_pkt.setUrg(urg);
		if (options.size()>0) tcp_pkt.options=options.toArray(new Option[]{});
		// check checksum
		tcp_pkt.checksum_check=0;
		int checksum=ByteUtils.twoBytesToInt(buf,off+OFFSET_CSUM);
		if (checksum!=0) {		
			if (dst_addr instanceof Ip4Address) checksum=Checksum.transportChecksum4(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_TCP,buf,off,len) & 0xffff;
			else if (dst_addr instanceof Ip6Address) checksum=Checksum.transportChecksum6(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_TCP,buf,off,len) & 0xffff;
			//if (checksum!=0x0000 && checksum!=0xffff) throw new RuntimeException("Wrong TCP checksum");
			if (checksum==0x0000 || checksum==0xffff) tcp_pkt.checksum_check=1;
			else tcp_pkt.checksum_check=-1;
		}
		return tcp_pkt;
	}


	/** Parses a TCP segment.
	 * @param ip_pkt IPv4 packet containing the TCP packet */
	public static TcpPacket parseTcpPacket(Ip4Packet ip_pkt) {
		IpAddress src_addr=(IpAddress)ip_pkt.getSourceAddress();
		IpAddress dst_addr=(IpAddress)ip_pkt.getDestAddress();
		return parseTcpPacket(src_addr,dst_addr,ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
	}

	
	/** Parses a UDP packet.
	 * @param ip_pkt IPv6 packet containing the TCP packet */
	public static TcpPacket parseTcpPacket(Ip6Packet ip_pkt) {
		IpAddress src_addr=(IpAddress)ip_pkt.getSourceAddress();
		IpAddress dst_addr=(IpAddress)ip_pkt.getDestAddress();
		return parseTcpPacket(src_addr,dst_addr,ip_pkt.getPayloadBuffer(),ip_pkt.getPayloadOffset(),ip_pkt.getPayloadLength());
	}


	/** Gets the source port number.
	 * @return source port */
	public int getSourcePort() {
		return src_port;
	}
	
	/** Gets the destination port number.
	 * @return destination port */
	public int getDestPort() {
		return dst_port;
	}

	/** Sets the sequence number.
	 * @param sqn sequence number */
	public void setSqn(long sqn) {
		this.sqn=sqn;
	}

	/** Gets the sequence number.
	 * @return the sequence number */
	public long getSqn() {
		return sqn;
	}

	/** Sets the ACK number.
	 * @param ack ACK number */
	public void setAck(long ack) {
		if (ack<0) ack=-1;
		this.ack=ack;
	}

	/** Gets the ACK number.
	 * @return the ACK number, or -1 if the flag is not present */
	public long getAck() {
		return ack;
	}

	/** Sets the SYN flag.
	 * @param val SYN flag value */
	public void setSyn(boolean val) {
		this.syn=val;
	}

	/** Gets the SYN flag value.
	 * @return SYN flag value */
	public boolean hasSyn() {
		return syn;
	}

	/** Sets the FIN flag.
	 * @param val FIN flag value */
	public void setFin(boolean val) {
		this.fin=val;
	}

	/** Gets the FIN flag value.
	 * @return FIN flag value */
	public boolean hasFin() {
		return fin;
	}

	/** Sets the PSH flag.
	 * @param val PSH flag value */
	public void setPsh(boolean val) {
		this.psh=val;
	}

	/** Gets the PSH flag value.
	 * @return PSH flag value */
	public boolean hasPsh() {
		return psh;
	}

	/** Sets the RST flag.
	 * @param val RST flag value */
	public void setRst(boolean val) {
		this.rst=val;
	}

	/** Gets the RST flag value.
	 * @return RST flag value */
	public boolean hasRst() {
		return rst;
	}

	/** Sets the URG pointer.
	 * @param urg URG pointer */
	public void setUrg(int urg) {
		if (urg<0) urg=-1;
		this.urg=urg;
	}

	/** Gets the URG pointer.
	 * @return the URG pointer, or -1 if the flag is not present */
	public int getUrg() {
		return urg;
	}

	/** Sets the flow window.
	 * @param fwin flow window */
	public void setWindow(int fwin) {
		this.window=fwin;
	}

	/** Gets the flow window.
	 * @return the flow window */
	public int getWindow() {
		return window;
	}

	/** Whether the checksum is correct, unspecified, wrong.
	 * @return 1= correct checksum, 0= unspecified checksum, -1= wrong checksum */
	public int getChecksumCheck() {
		return checksum_check;
	}

	/** Sets option list.
	 * @param options the new options */
	public void setOptions(Option[] options) {
		this.options=options;
	}

	/** Gets option list.
	 * @return options */
	public Option[] getOptions() {
		return options;
	}

	@Override
	public int getPacketLength() {
		if (options!=null) {
			int options_len=0;
			for (Option opt:options) options_len+=opt.getTotalLength();
			return 20+((options_len+3)/4)*4+data_len;
		}
		// else
		return 20+data_len;
	}
	
	@Override
	public int getBytes(byte[] buf, int off) {
		// header
		int total_len=getPacketLength();
		ByteUtils.intToTwoBytes(src_port,buf,off+OFFSET_SP);
		ByteUtils.intToTwoBytes(dst_port,buf,off+OFFSET_DP);	
		ByteUtils.intToFourBytes(sqn,buf,off+OFFSET_SQN);
		ByteUtils.intToFourBytes(ack>=0?ack:0,buf,off+OFFSET_ACK);
		int flags=(urg>=0?FLAG_URG:0)|(ack>=0?FLAG_ACK:0)|(psh?FLAG_PSH:0)|(rst?FLAG_RST:0)|(syn?FLAG_SYN:0)|(fin?FLAG_FIN:0);
		ByteUtils.intToTwoBytes(flags,buf,off+OFFSET_FLAGS);
		int hlen=total_len-data_len;
		buf[off+OFFSET_HLEN]=(byte)((hlen/4)<<4);
		ByteUtils.intToTwoBytes(window,buf,off+OFFSET_WIN);
		ByteUtils.intToTwoBytes(0,buf,off+OFFSET_CSUM);
		ByteUtils.intToTwoBytes(urg>=0?urg:0,buf,off+OFFSET_URG);
		if (options!=null) {
			int options_len=0;
			for (Option opt:options) options_len+=opt.getBytes(buf,off+OFFSET_OPTIONS+options_len);
			Arrays.fill(buf,off+OFFSET_OPTIONS+options_len,off+hlen,(byte)0);
		}
		
		// data
		if (data_len>0) System.arraycopy(data_buf,data_off,buf,off+hlen,data_len);
		// checksum
		int checksum=0;
		if (dst_addr instanceof Ip4Address) checksum=Checksum.transportChecksum4(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_TCP,buf,off,total_len);
		else if (dst_addr instanceof Ip6Address) checksum=Checksum.transportChecksum6(src_addr.getBytes(),dst_addr.getBytes(),Ip4Packet.IPPROTO_TCP,buf,off,total_len);
		ByteUtils.intToTwoBytes(checksum,buf,off+OFFSET_CSUM);
		checksum_check=1;
		return total_len;
	}

	/** Gets an IPv4 packet containing this TCP segment.
	 * @return the IPv4 packet */
	public Ip4Packet toIp4Packet() {
		return new Ip4Packet((Ip4Address)src_addr,(Ip4Address)dst_addr,Ip4Packet.IPPROTO_TCP,getBytes());
	}

	/** Gets an IPv6 packet containing this TCP segment.
	 * @return the IPv6 packet */
	public Ip6Packet toIp6Packet() {
		return new Ip6Packet((Ip6Address)src_addr,(Ip6Address)dst_addr,Ip6Packet.IPPROTO_TCP,getBytes());
	}

	/** Gets flags.
	 * @return a string representing the present flags */
	public String getFlags() {
		StringBuffer flags=new StringBuffer();
		if (syn) flags.append('S');
		if (fin) flags.append('F');
		if (rst) flags.append('R');
		if (ack>=0) flags.append('A');
		if (psh) flags.append('P');
		if (urg>=0) flags.append('U');
		return flags.toString();
	}

	@Override
	public String toString() {	
		StringBuffer sb=new StringBuffer();
		sb.append("TCP ");
		sb.append(new SocketAddress((IpAddress)src_addr,src_port)).append(" > ").append(new SocketAddress((IpAddress)dst_addr,dst_port));
		sb.append(" [").append(getFlags()).append(']');
		sb.append(" sqn=").append(sqn);
		if (ack>=0) sb.append(" ack=").append(ack);
		sb.append(" win=").append(window);
		if (options!=null) {
			for (Option opt:options) sb.append(" ").append(opt);
		}
		if (checksum_check<0) sb.append(" [wrong checksum]");
		sb.append(" datalen=").append(getPayloadLength());
		return sb.toString();	
	}
	
}
