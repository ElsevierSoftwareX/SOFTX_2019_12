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
import it.unipr.netsec.ipstack.tcp.TcpLayer;

import java.io.IOException;


/* Socket.
 */
public class Socket extends it.unipr.netsec.ipstack.tcp.Socket {

	/** Tcp layer */
	static TcpLayer tcp_layer=NetStack.TCP_LAYER;

	
	/** Creates an unconnected socket. */
	public Socket() {
		super(tcp_layer);
	}

	/** Creates an unconnected socket, specifying the type of proxy, if any, that should be used regardless of any other settings. */
	/*public Socket(Proxy proxy) {
	}*/

	/** Creates a stream socket and connects it to the specified port number at the specified IP address. */
	public Socket(InetAddress address, int port) throws IOException {
		super(tcp_layer,address,port);
	}

	/** Creates a stream socket and connects it to the specified port number on the named host. */
	public Socket(String host, int port) throws UnknownHostException, IOException {
		super(tcp_layer,host,port);
	}

	/** Creates a socket and connects it to the specified remote host on the specified remote port. The Socket will also bind() to the local address and port supplied. */
	public Socket(String host, int port, InetAddress localAddr, int localPort) throws IOException {
		super(tcp_layer,host,port,localAddr,localPort);
	}

	/** Creates a socket and connects it to the specified remote address on the specified remote port. The Socket will also bind() to the local address and port supplied. */
	public Socket(InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
		super(tcp_layer,address,port,localAddr,localPort);
	}

}
