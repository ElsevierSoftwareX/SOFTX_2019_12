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



/** Listener of a TCP connection.
 */
public interface TcpConnectionListener {

	/** When a new TCP connection is established.
	 * @param tcp_conn the new TCP connection */
	public void onConnected(TcpConnection tcp_conn);

	/** When a new data is received.
	 * @param tcp_conn the TCP connection
	 * @param buf buffer containing the received data
	 * @param off offset within the buffer
	 * @param len data length */
	public void onReceivedData(TcpConnection tcp_conn, byte[] buf, int off, int len);

	/** When the connection is closed by the remote entity.
	 * @param tcp_conn the TCP connection */
	public void onClose(TcpConnection tcp_conn);

	/** When the connection has been closed.
	 * @param tcp_conn the TCP connection */
	public void onClosed(TcpConnection tcp_conn);

	/** When the connection is reset by the remote entity.
	 * @param tcp_conn the TCP connection */
	public void onReset(TcpConnection tcp_conn);

}
