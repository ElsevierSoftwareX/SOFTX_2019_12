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

package it.unipr.netsec.rawsocket;


import java.net.SocketException;

import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.IpAddress;
import it.unipr.netsec.ipstack.ip6.Ip6Address;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.DataPacket;
import it.unipr.netsec.ipstack.tcp.TcpPacket;
import it.unipr.netsec.ipstack.udp.UdpPacket;


/** Unix socket. It wraps the standard C Unix socket interface.
 */
public class Socket {

	/** Sets debug mode.
	 * In debug mode, debug messages are printed on standard output.
	 * @param enable <i>true</i> for enabling debug mode; <i>false</i> for disabling debug mode */
	public static void setDebug(boolean enable) {
		setdebug(enable);
	}


	/** Loads the rawsock library */
	static {
		SystemUtils.loadLibrary("rawsck-64","rawsck-32","rawsck");
		startup();
	}
		
	/** Unspecified protocol family */
	public static final int PF_UNSPEC=0;
	/** Unix local interprocess communication */
	public static final int PF_UNIX=1;
	/** Local local interprocess communication (same as AF_UNIX) */
	public static final int PF_LOCAL=PF_UNIX;	
	/** IPv4 Internet protocol family */
	public static final int PF_INET=2;
	/** IPv6 Internet protocol family */
	//public static final int PF_INET6=10; // 10 for Unix, 23 for Windows
	public static final int PF_INET6=getPFINET6();
	/** Device-level communication */
	public static final int PF_PACKET=17;
	
	/* stream (connection) socket type */
	public static final int SOCK_STREAM=1;
	/* Datagram (conn.less) socket type */
	public static final int SOCK_DGRAM=2;
	/* Raw socket type */
	public static final int SOCK_RAW=3;
	/* Reliably-delivered message socket type */
	public static final int SOCK_RDM=4;
	/* Sequential packet socket type */
	public static final int SOCK_SEQPACKET=5;
	/* Linux specific way of getting packets at the dev level. For writing rarp and other similar things on the user level */
	public static final int SOCK_PACKET=10;
	
	/* Address to accept any incoming messages */
	//public static final int INADDR_ANY=0; // ((in_addr_t) 0x00000000)
	/* Address to send to all hosts */
	//public static final int INADDR_BROADCAST=-1; // ((in_addr_t) 0xffffffff)
	/* Address indicating an error return */
	//public static final int INADDR_NONE=-1; // ((in_addr_t) 0xffffffff)
	
	/** Socket identifier */
	int sockfd;

	/** Socket domain */
	int domain;

	/** Socket type */
	int type;

	/** Protocol number */
	int protocol;

	/** Whether has been bound */
	boolean is_bound;
	
	/** Receiver buffer */
	//byte[] recv_buffer=null;
 
	
   /** Creates a new socket.
	* @param domain specifies a communication domain; this selects the protocol family which will be used for communication
	* @param type specifies the communication semantics
	* @param protocol specifies a particular protocol to be used with the socket. If only a single protocol exists for a particular socket type, it can be specified as 0 */
	public Socket(int domain, int type, int protocol) {
		this.domain=domain;
		this.type=type;
		this.protocol=protocol;
		sockfd=socket(domain,type,protocol);
		if (sockfd<0) System.err.println("Error opening socket with domain="+domain+" type="+type+" protocol "+protocol);
		is_bound=false;
	}	
		
	/** Gets the socket domain.
	 * @return the socket domain */
	public int getDomain() {
		return domain;
	}
	
	/** Gets the socket type.
	 * @return the socket type */
	public int getType() {
		return type;
	}
	
	/** Gets the protocol number.
	 * @return the protocol number */
	public int getProtocol() {
		return protocol;
	}
	
	/** Closes the socket. */
	public void close() {
		if (sockfd>=0) close(sockfd);
	}
	
	/** Binds the socket to all local addresses. */
	public void bind() {
		if (domain==PF_INET || domain==PF_INET6) bind((IpAddress)null,0);
	}

	/** Binds the socket to the selected IP address and port.
	 * @param addr the IP address
	 * @param port the port number */
	public synchronized void bind(IpAddress addr, int port) { //throws SocketException {
		if (is_bound) return;
		// else
		if (addr==null) {
			if (domain==PF_INET) addr=Ip4Address.ADDR_UNSPECIFIED;
			else
			if (domain==PF_INET6) addr=Ip6Address.ADDR_UNSPECIFIED;
			// else?
			//else throw new java.net.SocketException("The domain must be PF_INET ("+PF_INET+") or PF_INET6 ("+PF_INET6+"): "+domain);
		}
		byte[] addr_bytes=addr!=null? addr.getBytes() : new byte[]{};
		bind(sockfd,domain,addr_bytes,port);
		is_bound=true;
	}

	/** Binds the socket to the selected Ethernet address.
	 * @param addr the Ethernet address 
	 * @throws SocketException */
	public synchronized void bind(EthAddress addr) throws SocketException {
		if (is_bound) return;
		if (domain!=PF_PACKET) throw new java.net.SocketException("The domain must be PF_PACKET ("+PF_PACKET+"): "+domain);
		if (addr==null) throw new java.net.SocketException("The address cannot be 'null'");
		// else		
		//if (addr==null) addr=EthAddress.BROADCAST_ADDRESS;
		bind(sockfd,domain,addr.getBytes(),0);
		is_bound=true;
	}

	/** Sends a packet.
	 * @param pkt the packet to be sent */
	public void send(DataPacket pkt) {
		Address dst_addr=pkt.getDestAddress();
		int dst_port=0;
		if (pkt instanceof UdpPacket) dst_port=((UdpPacket)pkt).getDestPort();
		else if (pkt instanceof TcpPacket) dst_port=((TcpPacket)pkt).getDestPort();
		// else ..
		sendto(pkt.getPayloadBuffer(),pkt.getPayloadOffset(),pkt.getPayloadLength(),0,dst_addr.toString(),dst_port);
	}

	/** Sends a raw data.
	 * @param buf the buffer containing the packet. Whether the buffer should include also the packet header or not, depends on the type of socket, protocol, and configured options
	 * @param off the offset within the buffer
	 * @param len the data length
	 * @param flags flags (if any)
	 * @param dest_addr the destination address
	 * @param dest_port the destination port (if applicable)
	 * @return the number of characters sent, in case of success; -1 on error */
	public int sendto(byte[] buf, int off, int len, int flags, String dest_addr, int dest_port) {
		if (sockfd<0) return -1;
		// else
		if (!is_bound) bind();
		return sendto(sockfd,buf,off,len,flags,domain,dest_addr,dest_port);
	}
	
	/** Receives a packet.
	  * <p> This method is blocking, that is it returns only when a packet is received.
	  * @param pkt the packet used for returning the incoming packet */
	public void receive(DataPacket pkt) {
		if (!is_bound) bind();
		byte[] buf=pkt.getPayloadBuffer();
		int off=pkt.getPayloadOffset();
		int len=recv(buf,off,0);
		pkt.setPayloadLength(len);
	}
	
	/** receives raw data.
	 * <p> This method is blocking, that is it returns only when a packet is received.
	 * @param buf the buffer used for returning the entire received packet
	 * @param off the offset within the buffer
	 * @param flags flags (if any)
	 * @return the length of the received packet */
	public int recv(byte[] buf, int off, int flags) {
		if (sockfd<0) return -1;
		// else
		if (!is_bound) bind();
		return recv(sockfd,buf,off,flags);
	}
	
	/** receives raw data with source socket address.
	 * <p> This method is blocking, that is it returns only when a packet is received.
	 * @param buf the buffer used for returning the entire received packet
	 * @param off the offset within the buffer
	 * @param flags flags (if any)
	 * @param addr the buffer used for returning the source address
	 * @param port the buffer used for returning the source port
	 * @return the length of the received packet */
	public int recvfrom(byte[] buf, int off, int flags, byte[] addr, byte[] port) {
		if (sockfd<0) return -1;
		// else
		if (!is_bound) bind();
		return recvfrom(sockfd,buf,off,flags,addr,port);
	}
	
	/** Sets a given socket option.
	 * @param level the option level
	 * @param optname the option number
	 * @param optval the buffer containing the option
	 * @param off the offset within the buffer 
	 * @param len the length of the option
	 * @return zero on success; -1 on error */
	public int setsockopt(int level, int optname, byte[] optval, int off, int len) {
		if (sockfd<0) return -1;
		// else
		if (!is_bound) bind();
		return setsockopt(sockfd,level,optname,optval,off,len);
	}
	
	/** Gets a given socket option.
	 * @param level the option level
	 * @param optname the option number
	 * @param optval the buffer used to return the option
	 * @param off the offset within the buffer 
	 * @return the length of the option on success, -1 on error (Note: differently, the original unix getsockopt() method returns zero on success; -1 on error; the option length is returned within an extra parameter) */
	public int getsockopt(int level, int optname, byte[] optval, int off) {
		if (sockfd<0) return -1;
		// else
		if (!is_bound) bind();
		return getsockopt(sockfd,level,optname,optval,off);
	}

	
	// *************************** Native methods: ***************************

	/** Starts the winsock2. */
	private static native void startup();
	 
	/** Cleans the winsock2. */
	private static native void cleanup();
	 
	/** Gets the PF_INET6 value (10 for Unix, 23 for Windows).
	 * @return PF_INET6 value */
	private static native int getPFINET6();

	/** Sets debug mode.
	 * @param enable <i>true</i> for enabling debug mode; <i>false</i> for disabling debug mode */
	private static native void setdebug(boolean enable);

	/** Creates the socket.
	* @param domain specifies a communication domain; this selects the protocol family which will be used for communication
	* @param type specifies the communication semantics
	* @param protocol specifies a particular protocol to be used with the socket. If only a single protocol exists for a particular socket type, it can be specified as 0
	* @return the new socket identifier in case of success, -1 on error */
	private native int socket(int domain, int type, int protocol);
	 
	/** Closes the raw socket.
	 * @param sockfd socket identifier */
	private native void close(int sockfd);    

	/** Binds the socket.
	* @param sockfd socket identifier
	* @param sa_family the address family (usually equal to the socket domain)
	* @return zero on success, -1 on error */
	//private native int bindAllAddresses(int sockfd, int sa_family);
	
	/** Binds the socket.
	* @param sockfd socket identifier
	* @param sa_family the address family (usually equal to the socket domain)
	* @param addr the local address
	* @param port the local port (if applicable)
	* @param datalen data length
	* @return zero on success, -1 on error */
	private native int bind(int sockfd, int sa_family, byte[] addr, int port);
	 
	/** Binds the socket.
	* @param sockfd socket identifier
	* @param addr the local address (family and data)
	* @param addrlen address length
	* @return zero on success, -1 on error */
	//private native int bind(int sockfd, byte[] addr, int addrlen);
	 
	/** Sends a raw data.
	 * @param sockfd socket identifier
	 * @param buf the buffer containing the packet data
	 * @param off the offset within the buffer
	 * @param len the data length
	 * @param flags flags (if any)
	 * @return the number of characters sent, in case of success; -1 on error */
	//private native int send(int sockfd, byte[] buf, int off, int len, int flags);
	
	/** Sends a raw data.
	 * @param sockfd socket identifier
	 * @param data the buffer containing the packet data
	 * @param off the offset within the buffer
	 * @param len the data length
	 * @param flags flags (if any)
	 * @param sa_family the address family (usually equal to the socket domain)
	 * @param dst_addr the destination address
	 * @param dest_port the destination port (if applicable)
	 * @return the number of characters sent, in case of success; -1 on error */
	private native int sendto(int sockfd, byte[] data, int off, int len, int flags, int sa_family, String dest_addr, int dest_port);

	/** Sends raw data.
	 * @param sockfd socket identifier
	 * @param buf the buffer containing the packet data
	 * @param off the offset within the buffer
	 * @param len the data length
	 * @param flags flags (if any)
	 * @param dst_addr the destination address
	 * @param dest_port the destination port (if applicable)
	 * @return the number of characters sent, in case of success; -1 on error */
	//private native int sendto(int sockfd, byte[] buf, int off, int len, int flags, int sa_family, byte[] dst_addr, int port);
	
	/** receives raw data.
	 * @param sockfd socket identifier
	 * @param buf the buffer used for returning the received packet
	 * @param flags flags (if any)
	 * @return the length of the received packet */
	private native int recv(int sockfd, byte[] buf, int off, int flags);

	/** receives raw data.
	 * @param sockfd socket identifier
	 * @param buf the buffer used for returning the received packet
	 * @param flags flags (if any)
	 * @param addr buffer for returning the source address
	 * @param port buffer for returning the source port
	 * @return the length of the received packet */
	private native int recvfrom(int sockfd, byte[] buf, int off, int flags, byte[] addr, byte[] port);	
	
	/** Sets a given socket option.
	 * @param sockfd socket identifier
	 * @param level the option level
	 * @param optname the option number
	 * @param optval the buffer containing the option
	 * @param off the offset within the buffer 
	 * @param len the length of the option
	 * @return zero on success; -1 on error */
	private native int setsockopt(int sockfd, int level, int optname, byte[] optval, int off, int len);

	/** Gets a given socket option.
	 * @param sockfd socket identifier
	 * @param level the option level
	 * @param optname the option number
	 * @param optval the buffer used to return the option
	 * @param off the offset within the buffer 
	 * @return the length of the option on success, -1 on error (Note: differently, the original unix getsockopt() method returns zero on success; -1 on error; the option length is returned within an extra parameter) */
	private native int getsockopt(int sockfd, int level, int optname, byte[] optval, int off);

}
