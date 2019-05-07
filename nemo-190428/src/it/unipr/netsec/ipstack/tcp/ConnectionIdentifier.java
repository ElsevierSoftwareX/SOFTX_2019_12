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


import java.util.Arrays;

import it.unipr.netsec.ipstack.ip4.SocketAddress;


/** Connection identifier.
 * It is the tuple formed by local address, local port, remote address, remote port.
 */
public class ConnectionIdentifier {

	/** Local socket address */
	SocketAddress local_soaddr;
	
	/** Remote socket address */
	SocketAddress remote_soaddr;
	
	
	/** Creates a new Tconnection identifier.
	 * @param ci a connection identifier */
	protected ConnectionIdentifier(ConnectionIdentifier ci) {
		this.local_soaddr=ci.local_soaddr;
		this.remote_soaddr=ci.remote_soaddr;
	}

	/** Creates a new connection identifier.
	 * @param local_soaddr local socket address
	 * @param remote_soaddr remote socket address */
	public ConnectionIdentifier(SocketAddress local_soaddr, SocketAddress remote_soaddr) {
		this.local_soaddr=local_soaddr;
		this.remote_soaddr=remote_soaddr;
	}
	
	/** Gets the local socket address.
	 * @return the socket address */
	public SocketAddress getLocalSocketAddress() {
		return local_soaddr;
	}

	/** Gets the remote socket address.
	 * @return the socket address */
	public SocketAddress getRemoteSocketAddress() {
		return remote_soaddr;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ConnectionIdentifier) {
			ConnectionIdentifier ci=(ConnectionIdentifier)obj;
			if (local_soaddr.equals(ci.local_soaddr) && remote_soaddr.equals(ci.remote_soaddr)) return true;
		}
		// else
		return false;
	}

	@Override
	public int hashCode() {
		byte[] buf=new byte[local_soaddr.length()+remote_soaddr.length()];
		int len=local_soaddr.getBytes(buf,0);
		len+=remote_soaddr.getBytes(buf,len);
		return Arrays.hashCode(buf);
	}

	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append(local_soaddr).append(':').append(remote_soaddr);
		return sb.toString();
	}

}
