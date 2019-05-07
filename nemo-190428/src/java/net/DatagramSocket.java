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

package java.net;


import it.unipr.netsec.ipstack.netstack.NetStack;


/** UDP socket.
 */
public class DatagramSocket extends it.unipr.netsec.ipstack.udp.DatagramSocket {
	
	/** Static attribute for detecting the current implementation */
	public static final String PROVIDER="ipstack";

	
	/** Creates a datagram socket and binds it to any available port on the local host machine. */
	public DatagramSocket() throws SocketException {
		super(NetStack.UDP_LAYER);
	}

	/** Creates an unbound datagram socket with the specified DatagramSocketImpl. */
	/*protected DatagramSocket(DatagramSocketImpl impl) {
	}*/

	/** Creates a datagram socket and binds it to the specified port on the local host machine. */
	public DatagramSocket(int port) throws SocketException {
		super(NetStack.UDP_LAYER,port);
	}

	/** Creates a datagram socket, bound to the specified local address. */
	public DatagramSocket(int port, InetAddress laddr) throws SocketException {
		super(NetStack.UDP_LAYER,port,laddr);
	}

	/** Creates a datagram socket, bound to the specified local socket address. */
	public DatagramSocket(SocketAddress bindaddr) throws SocketException {
		super(NetStack.UDP_LAYER,bindaddr);
	}

}
