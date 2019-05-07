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


import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip4.SocketAddress;
import it.unipr.netsec.ipstack.tcp.option.MaximumSegmentSizeOption;
import it.unipr.netsec.ipstack.tcp.option.Option;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;

import org.zoolu.util.Clock;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;


/** A TCP connection.
 */
public class TcpConnection {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,toString()+": "+str);
	}

	// CONSTANTS:
	
	static int max_retransmissions=10;
	
	// STATE:
	
	/** TCP States */
	protected static enum State {
		LISTEN,
		SYN_SENT,
		SYN_RECEIVED,
		ESTABLISHED,
		FIN_WAIT_1,
		FIN_WAIT_2,
		CLOSE_WAIT,
		CLOSING,
		LAST_ACK,
		TIME_WAIT,
		CLOSED
	}
	
	/** TCP State */
	State state=State.LISTEN;

	// SENDER:

	/** Initial send sequence number */
	long snd_isn=0xffffffffL&new Random().nextInt();

	/** Oldest unacknowledged sequence number */
	long snd_una=snd_isn;

	/** Next sequence number to be sent */
	long snd_nxt=snd_isn;

	/** Send window */
	int snd_wnd=8192;
	
	/** Send urgent pointer */
	long snd_up;
	
	/** Segment sequence number used for last window update */
	long snd_wl1;

	/** Segment acknowledge number used for last window update */
	long snd_wl2;

	// RECEIVER:

	/** Initial receive sequence number */
	long rcv_isn=-1;

	/** Next sequence number expected to be received */
	long rcv_nxt=-1;

	/** Receive window */
	int rcv_wnd=65535;
	
	/** Receive urgent pointer */
	long rcv_up;

	/** Final receive sequence number (SQN of received FIN) */
	long rcv_fsn=-1;

	// COUNTER:
	
	/** Count the number of repeated ACKs */
	long debug_snd_una_count=0;	

	// TIMEOUT:
		
	/** Retransmission timeout (milliseconds) */
	long retransmission_to=200;
	
	/** Closing timeout (milliseconds) */
	long closing_to=4000;
	
	// LAYER:
	
	/** TCP layer */
	TcpLayer tcp_layer;

	/** Connection listener */
	TcpConnectionListener listener;

	/** Local IP address */
	IpAddress local_ipaddr;
	
	/** Local port */
	int local_port;

	/** Connection identifier */
	ConnectionIdentifier ci;

	/** Sender buffer with unacknowledged segments */
	ArrayList<PacketTimer> snd_buffer=new ArrayList<PacketTimer>();

	/** Receiver buffer with out-of-line segments*/
	ChunkBuffer rcv_buffer;

	/** Listen transmission time-outs */
	PacketTimerListener transmission_listener=new PacketTimerListener() {
		@Override
		public void onTimeout(PacketTimer t) {
			processTransmissionTimeout(t);
		}		
	};

	
	// PUBLIC METHODS:

	/** Creates an new TCP connection.
	 * @param tcp_layer the TCP layer
	 * @param local_ipaddr local IP address to bind this connection (or null)
	 * @param local_port if &gt;0 it is the local port to bind this connection
	 * @param listener connection listener */
	public TcpConnection(TcpLayer tcp_layer, IpAddress local_ipaddr, int local_port, TcpConnectionListener listener) {
		this.tcp_layer=tcp_layer;
		this.local_ipaddr=local_ipaddr;
		this.local_port=local_port;
		this.listener=listener;
		if (DEBUG) debug("TcpConnection()");
	}
	
	/** Listens for an incoming connection.  */
	public void listen() throws IOException {
		if (state!=State.LISTEN) {
			if (DEBUG) debug("listen(): cannot listen when in state: "+state);
			return;
		}
		// else
		if (local_port<=0) tcp_layer.getFreePort();
		if (DEBUG) debug("listen(): "+local_port);
		// else
		TcpLayerListener this_tcp_layer_listener=new TcpLayerListener(){
			@Override
			public void onReceivedPacket(TcpLayer tcp_layer, TcpPacket tcp_pkt) {
				processReceivedPacket(tcp_layer,tcp_pkt);
			}
		};
		tcp_layer.setListener(local_port,this_tcp_layer_listener);
	}
	
	/** Connects to a remote socket address. 
	 * @throws IOException */
	public void connect(SocketAddress remote_soaddr) throws IOException {
		if (DEBUG) debug("connect(): "+remote_soaddr);
		if (state!=State.LISTEN) {
			if (DEBUG) debug("connect(): cannot connect when in state: "+state);
			return;
		}
		if (local_port<=0) tcp_layer.getFreePort();
		if (local_ipaddr==null) local_ipaddr=tcp_layer.getSourceAddress(remote_soaddr.getIpAddress());
		if (local_ipaddr==null) throw new IOException("No route for the given destination: "+remote_soaddr);
		// else
		ci=new ConnectionIdentifier(new SocketAddress(local_ipaddr,local_port),remote_soaddr);
		TcpLayerListener this_tcp_layer_listener=new TcpLayerListener(){
			@Override
			public void onReceivedPacket(TcpLayer tcp_layer, TcpPacket tcp_pkt) {
				processReceivedPacket(tcp_layer,tcp_pkt);
			}
		};
		tcp_layer.setListener(ci,this_tcp_layer_listener);
		synchronized (state) {
			changeState(State.SYN_SENT);
			sendSyn();
		}
	}
	
	/** Closes the connection. */
	public void close() {
		synchronized (state) {
			if (state==State.ESTABLISHED || state==State.SYN_RECEIVED) {
				changeState(State.FIN_WAIT_1);
				sendFin(rcv_nxt);
			}
			else
			if (state==State.SYN_SENT) {
				changeState(State.CLOSED);
			}
			else
			if (state==State.CLOSE_WAIT) {
				changeState(State.LAST_ACK);
				sendFin(rcv_nxt);			
			}			
		}
	}
	
	public void reset() {
		TcpPacket tcp_rst=createSegment(-1,null);
		tcp_rst.setRst(true);
		changeState(State.TIME_WAIT);
		send(tcp_rst);
	}
	
	/** Sends a block of bytes. */
	public void send(byte[] data) {
		send(data,0,data.length);
	}
	
	/** Sends a block of bytes. */
	public synchronized void send(byte[] buf, int off, int len) {
		if (len>0) {
			TcpPacket tcp_pkt=createSegment(rcv_nxt,buf,off,len);
			tcp_pkt.setPsh(true);
			snd_nxt+=len;
			transmit(tcp_pkt);
		}
	}
	
	/** Whether it is connected. */
	public boolean isConnected() {
		return state==State.ESTABLISHED;
	}

	/** Whether it is closed. */
	public boolean isClosed() {
		return state==State.CLOSED;
	}
	
	/** Sends a segment with transmission time-out. */
	void transmit(TcpPacket tcp_pkt) {
		synchronized (snd_buffer) {
			PacketTimer t=new PacketTimer(tcp_pkt,transmission_listener);
			snd_buffer.add(t);			
			transmit(t);
		}
	}

	/** Re-sends a segment with transmission time-out. */
	void transmit(PacketTimer t) {
		t.start(retransmission_to);
		/*// ##########################################
		TcpPacket tcp_pkt=t.getPacket();
		if (tcp_pkt.getPayloadLength()>0) {
			StringBuffer sb=new StringBuffer();
			sb.append(""+tcp_pkt.getDestPort()+"*");
			sb.append("\t"+tcp_pkt.getSqn());
			sb.append("\t"+tcp_pkt.getPayloadLength());
			sb.append("\t"+new String(tcp_pkt.getPayloadBuffer(),tcp_pkt.getPayloadOffset(),2));
			if (rcv_buffer!=null) {
				sb.append("\t");
				for (Chunk c: rcv_buffer.getChunks()) {
					sb.append(c);
				}
			}
			System.err.println(sb.toString());
		}
		*/// ##########################################
		
		send(t.getPacket());
	}

	/** Sends a segment. */
	void send(TcpPacket tcp_pkt) {
		//if (tcp_pkt.getAck()>=0) tcp_pkt.setAck((rcv_fsn>0 && rcv_fsn==rcv_nxt)?rcv_nxt+1:rcv_nxt);
		if (DEBUG) debug("SEND: sqn="+(snd_isn>=0?tcp_pkt.getSqn()-snd_isn:0)+" ack="+(rcv_isn>=0?tcp_pkt.getAck()-rcv_isn:0)+": "+tcp_pkt);
		tcp_layer.send(tcp_pkt);
	}

	/** Processes an incoming packet. */
	void processReceivedPacket(TcpLayer tcp_layer, TcpPacket tcp_pkt) {
		if (DEBUG) debug("RECV: sqn="+(rcv_isn>=0?tcp_pkt.getSqn()-rcv_isn:0)+" ack="+(snd_isn>=0?tcp_pkt.getAck()-snd_isn:0)+": "+tcp_pkt);
		/*// ##########################################
		if (tcp_pkt.getPayloadLength()>0) {
			StringBuffer sb=new StringBuffer();
			sb.append(""+tcp_pkt.getDestPort());
			sb.append("\t"+tcp_pkt.getSqn());
			sb.append("\t"+tcp_pkt.getPayloadLength());
			sb.append("\t"+new String(tcp_pkt.getPayloadBuffer(),tcp_pkt.getPayloadOffset(),2));
			if (rcv_buffer!=null) {
				sb.append("\t");
				for (Chunk c: rcv_buffer.getChunks()) {
					sb.append(c);
				}
			}
			System.err.println(sb.toString());
		}
		*/// ##########################################
		
		// initialize the connection identifier
		if (ci==null) {
			local_ipaddr=(IpAddress)tcp_pkt.getDestAddress();
			ci=new ConnectionIdentifier(new SocketAddress(local_ipaddr,tcp_pkt.getDestPort()),new SocketAddress((IpAddress)tcp_pkt.getSourceAddress(),tcp_pkt.getSourcePort()));
			if (DEBUG) debug("processReceivedPacket(): ci: "+ci);
		}
		
		// check flags
		int flag_count=0;
		if (tcp_pkt.hasSyn()) flag_count++;
		if (tcp_pkt.hasFin()) flag_count++;
		if (tcp_pkt.hasRst()) flag_count++;
		if (flag_count>1) {
			if (DEBUG) debug("processIncomingPacket(): WARNING: invalid flags ["+tcp_pkt.getFlags()+"]: discarded");
			return;			
		}
		// check sequence number
		long sqn=tcp_pkt.getSqn();
		if (rcv_isn>=0 && sqn<rcv_isn) {
			if (DEBUG) debug("processIncomingPacket(): WARNING: sequence number less than isqn ("+sqn+"<"+rcv_isn+"): discarded");
			return;		
		}
		// process ACK
		long ack=tcp_pkt.getAck();
		if (ack>0) {
			if (ack<snd_isn) {
				if (DEBUG) debug("processIncomingPacket(): WARNING: ack number less than isqn ("+ack+"<"+snd_isn+"): discarded");
				return;
			}
			// else
			if (ack>snd_nxt) {
				if (DEBUG) debug("processIncomingPacket(): WARNING: ack number greater than next ("+ack+">"+snd_nxt+"): discarded");
				return;
			}
			// else
			if (snd_una<ack/* && ack<=snd_nxt*/) {
				synchronized (snd_buffer) {
					for (int i=0; i<snd_buffer.size(); i++) {
						PacketTimer t=snd_buffer.get(i);
						if (lastSequenceNumber(t.getPacket())<ack) {
							t.done();
							snd_buffer.remove(i);
							i--;
						}
					}
					snd_una=ack;
					debug_snd_una_count=0;					
				}
			}
			else
			if (snd_una==ack && snd_una<snd_nxt) {
				debug_snd_una_count++;
				if (DEBUG) debug("processIncomingPacket(): repeated ack ("+(snd_una-snd_isn)+"): "+debug_snd_una_count);
			}
			// ACK of SYN,ACK
			if (state==State.SYN_RECEIVED) {
				changeState(State.ESTABLISHED);
			}
			// ACK of FIN
			if (ack==snd_nxt) {
				if (state==State.FIN_WAIT_1) {
					changeState(State.FIN_WAIT_2);
				}
				else
				if (state==State.LAST_ACK) {
					changeState(State.CLOSED);
				}
				else
				if (state==State.CLOSING) {
					changeState(State.TIME_WAIT);
				}
			}
		}
		// process RST,SYN,FIN,DATA
		int len=tcp_pkt.getPayloadLength();
		synchronized (state) {
			// RST
			if (tcp_pkt.hasRst()) {
				if (rcv_nxt>=0 && sqn<rcv_nxt) {
					if (DEBUG) debug("processIncomingPacket(): WARNING: RST wrong sequence number ("+sqn+"<"+rcv_nxt+"): discarded");
					return;
				}
				// else
				if (state!=State.CLOSED) {
					changeState(State.CLOSED);
					sendAck();
					return;
				}
			}
			else
			// SYN
			if (tcp_pkt.hasSyn()) {
				if (state==State.LISTEN) {
					tcp_layer.removeListener(local_port);
					TcpLayerListener this_tcp_layer_listener=new TcpLayerListener(){
						@Override
						public void onReceivedPacket(TcpLayer tcp_layer, TcpPacket tcp_pkt) {
							processReceivedPacket(tcp_layer,tcp_pkt);
						}
					};
					tcp_layer.setListener(ci,this_tcp_layer_listener);
					rcv_isn=sqn;
					rcv_nxt=rcv_isn+1;
					changeState(State.SYN_RECEIVED);
					sendSynAck();
				}
				else
				if (state==State.SYN_RECEIVED) {
					sendSynAck();
				}
				else
				if (state==State.SYN_SENT) {
					rcv_isn=sqn;
					rcv_nxt=rcv_isn+1;
					if (ack>=0) {
						changeState(State.ESTABLISHED);
					}
					else {
						changeState(State.SYN_RECEIVED);
					}
					sendAck();
				}
				else
				if (state==State.ESTABLISHED) {
					sendAck();
				}
			}
			// DATA, FIN
			else {
				// DATA
				if (len>0) {
					if (rcv_buffer==null) rcv_buffer=new ChunkBuffer(rcv_isn+1);
					Chunk c=new Chunk(tcp_pkt.getSqn()+(tcp_pkt.hasSyn()?1:0),tcp_pkt.getPayloadBuffer(),tcp_pkt.getPayloadOffset(),tcp_pkt.getPayloadLength());
					rcv_buffer.write(c);
					if (DEBUG) debug("processIncomingPacket(): rcv_buffer: "+rcv_buffer.toString());
					byte[] data=null;
					if (rcv_buffer.available()>0) {
						data=rcv_buffer.read();
						rcv_nxt+=data.length;
						if (DEBUG) debug("processIncomingPacket(): data len: "+data.length);
					}
					else {
						if (DEBUG) debug("processIncomingPacket(): out-of-sequence data: "+(sqn-rcv_isn)+"["+len+"]");
					}
					sendAck();
					if (state==State.ESTABLISHED && data!=null) listener.onReceivedData(this,data,0,data.length);
					
					/*if (sqn==rcv_nxt) {
						rcv_nxt+=len;
						sendAck();
						listener.onReceivedData(this,tcp_pkt.getPayloadBuffer(),tcp_pkt.getPayloadOffset(),tcp_pkt.getPayloadLength());
					}
					else {
						if (DEBUG) debug("processIncomingPacket(): out-of-sequence data: "+(sqn-rcv_isn)+"["+len+"]");
						sendAck();
					}*/
				}
				// FIN
				if (tcp_pkt.hasFin()) {
					long syn_sqn=sqn+len;
					if (rcv_fsn<0) {
						if (syn_sqn<rcv_buffer.end()) {
							if (DEBUG) debug("processIncomingPacket(): WARNING: FIN wrong sequence number ("+syn_sqn+"<"+rcv_buffer.end()+"): discarded");
							return;	
						}
						rcv_fsn=syn_sqn;
						if (DEBUG) debug("processIncomingPacket(): FIN sequence number: "+rcv_fsn);
					}
					else
					if (syn_sqn!=rcv_fsn) {
						if (DEBUG) debug("processIncomingPacket(): WARNING: FIN wrong sequence number ("+syn_sqn+"!="+rcv_fsn+"): discarded");
						return;
					}				

					if (state==State.ESTABLISHED) {
						changeState(State.CLOSE_WAIT);
						sendAck();
					}
					else
					if (state==State.FIN_WAIT_1) {
						changeState(State.CLOSING);					
						sendAck();
					}
					else
					if (state==State.FIN_WAIT_2) {
						changeState(State.TIME_WAIT);
						sendAck();
					}
					else
					if (state==State.CLOSE_WAIT || state==State.CLOSING  || state==State.TIME_WAIT) {
						sendAck();
					}
				}
			}
		}
	}

	// PRIVATE METHODS

	private boolean isAcceptable(TcpPacket tcp_pkt) {
		long sqn=tcp_pkt.getSqn();
		int len=tcp_pkt.getPayloadLength();
		if (tcp_pkt.hasSyn() || tcp_pkt.hasFin()) len++;
		boolean acceptable;
		if (len==0 && rcv_wnd==0 && sqn==rcv_nxt) acceptable=true;
		else
		if (len==0 && rcv_wnd>0 && rcv_nxt<=sqn && sqn<rcv_nxt+rcv_wnd) acceptable=true;
		else
		if (len>0 && rcv_wnd==0) acceptable=false;
		else
		if ((rcv_nxt<=sqn && sqn<rcv_nxt+rcv_wnd) && (rcv_nxt<=sqn+len-1 && sqn+len-1<rcv_nxt+rcv_wnd)) acceptable=true;
		else acceptable=false;
		
		if (!acceptable) {
			if (DEBUG) debug("WARNING: the segment is not acceptable: sqn="+sqn+", len="+len+", rcv_nxt="+rcv_nxt+", rcv_wnd="+rcv_wnd);
		}
		return acceptable;
	}

	private synchronized void changeState(State state) {
		if (DEBUG) debug("changeState(): "+this.state+"-->"+state);
		if (this.state!=state && this.state!=State.CLOSED) {
			this.state=state;
			if (state==State.ESTABLISHED) {
				listener.onConnected(this);
			}
			if (state==State.CLOSED) {
				synchronized (snd_buffer) {
					while (snd_buffer.size()>0) {
						snd_buffer.get(0).done();
						snd_buffer.remove(0);
					}
				}					
				tcp_layer.removeListener(ci);
				listener.onClosed(TcpConnection.this);
				listener=null;
			}
			else
			if (state==State.CLOSING || state==State.CLOSE_WAIT) {
				listener.onClose(this);
			}
			else
			if (state==State.TIME_WAIT) {
				Timer t=Clock.getDefaultClock().newTimer(closing_to,0,new TimerListener(){
					@Override
					public void onTimeout(Timer t) {
						changeState(State.CLOSED);
					}	
				});
				t.start();
			}
		}
		else {
			if (DEBUG) debug("changeState(): state not changed or already closed");			
		}
	}
	
	private void processTransmissionTimeout(PacketTimer t) {
		TcpPacket tcp_pkt=t.getPacket();
		int count=t.getCounter();
		if (DEBUG) debug("processTransmissionTimeout(): sqn="+(tcp_pkt.getSqn()-snd_isn)+", cnt="+count);
		if (count<max_retransmissions) {
			if (tcp_pkt.getAck()>=0) tcp_pkt.setAck(getAckNumber());
			transmit(t);
		}
		else {
			if (DEBUG) debug("processTransmissionTimeout(): maximum number of retransmissions");
			reset();
		}
	}
	
	private long lastSequenceNumber(TcpPacket tcp_pkt) {
		long val=tcp_pkt.getSqn()+tcp_pkt.getPayloadLength()-1;
		if (tcp_pkt.hasSyn()) val++;
		if (tcp_pkt.hasFin()) val++;
		return val;
	}

	private TcpPacket createSegment(long ack, byte[] data) {
		return createSegment(ack,data,0,data!=null?data.length:0);
	}
	
	private TcpPacket createSegment(long ack, byte[] buf, int off, int len) {
		SocketAddress remote_soaddr=ci.getRemoteSocketAddress();
		return new TcpPacket(local_ipaddr,local_port,remote_soaddr.getIpAddress(),remote_soaddr.getPort(),snd_nxt,ack,buf,off,len);
	}

	private void sendSyn() {
		TcpPacket tcp_syn=createSegment(-1,null);
		tcp_syn.setSqn(snd_isn);
		tcp_syn.setSyn(true);
		snd_nxt=snd_isn+1;
		tcp_syn.setOptions(new Option[]{ new MaximumSegmentSizeOption(1460) });
		transmit(tcp_syn);
	}

	private void sendFin(long ack_num) {
		TcpPacket tcp_fin=createSegment(ack_num,null);
		tcp_fin.setFin(true);
		snd_nxt+=1;
		transmit(tcp_fin);
	}

	private void sendSynAck() {
		TcpPacket tcp_syn_ack=createSegment(rcv_nxt,null);
		tcp_syn_ack.setSyn(true);
		snd_nxt=snd_isn+1;
		tcp_syn_ack.setSqn(snd_isn);
		tcp_syn_ack.setOptions(new Option[]{ new MaximumSegmentSizeOption(1460) });
		transmit(tcp_syn_ack);
	}

	private void sendAck() {
		TcpPacket tcp_ack=createSegment(getAckNumber(),null);
		send(tcp_ack);
	}

	private long getAckNumber() {
		return (rcv_fsn>0 && rcv_fsn==rcv_nxt)?rcv_nxt+1:rcv_nxt;
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName()+"["+(ci!=null? ci : local_port)+"]";
	}

}
