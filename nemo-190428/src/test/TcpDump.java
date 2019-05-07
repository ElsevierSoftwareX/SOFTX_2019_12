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

package test;


import java.io.IOException;


/** It analyzes all packets captured at data-link level.
 * <p> 
 * It uses {@link it.unipr.netsec.rawsocket.RawLinkSocket}, that in turn uses a PF_PACKET SOCK_RAW socket.
 * Since PF_PACKET SOCK_RAW sockets are not supported neither in Windows OS neither nor in Mac OS,
 * TcpDump can be run only on Linux OS.
 */
public class TcpDump {
	
	/** The main method. 
	 * @throws IOException */
	public static void main(String[] args) throws IOException {	
		it.unipr.netsec.rawsocket.examples.TcpDump.main(args);
	}
}
