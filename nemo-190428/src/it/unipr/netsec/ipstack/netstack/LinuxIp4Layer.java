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

package it.unipr.netsec.ipstack.netstack;


import java.io.IOException;

import it.unipr.netsec.ipstack.ip4.Ip4Layer;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingTable;


/** IPv4 {@link it.unipr.netsec.ipstack.ip4.Ip4Layer layer} that loads network configuration from a configuration file containing linux commands.
 */
public class LinuxIp4Layer extends Ip4Layer {
		
	//private static Route[] temp_routing_table=null;
	

	/** Creates a new IPv4 layer.
	 * @param config IPv4 configuration 
	 * @throws IOException */
	public LinuxIp4Layer(NetConfiguration config) throws IOException {
		super(config.getNetInterfaces());
		Route[] routes=config.getRoutes();
		RoutingTable rt=getRoutingTable();
		for (Route r: routes) rt.add(r);
	}
	
	/** Creates a new IPv4 layer.
	 * @param config_file configuration file name 
	 * @throws IOException */
	/*public LinuxIp4Layer(String config_file) throws IOException {
		super(readConfiguration(new LinuxIp4Configuration(config_file)));
		RoutingTable rt=getRoutingTable();
		for (Route r: temp_routing_table) rt.add(r);
	}*/
	
	/*private static NetInterface[] readConfiguration(NetConfiguration config) throws IOException {
		temp_routing_table=config.getRoutes();
		return config.getNetInterfaces();
	}*/

}
