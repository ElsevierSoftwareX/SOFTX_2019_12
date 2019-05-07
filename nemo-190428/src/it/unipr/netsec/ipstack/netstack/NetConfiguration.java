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


import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.routing.Route;

import java.io.IOException;


public interface NetConfiguration {

	/** Adds a configuration command.
	 * @param command the configuration command
	 * @return this object
	 * @throws IOException */
	public NetConfiguration add(String command) throws IOException;

	/** Adds a network interface.
	 * @param name the network interface name
	 * @param ni the network interface
	 * @return this object */
	public NetConfiguration add(String name, NetInterface ni);

	/** Adds a route.
	 * @param r the route
	 * @return this object */
	public NetConfiguration add(Route r);

	/** Gets network interfaces. */
	public NetInterface[] getNetInterfaces();
	
	/** Gets routes. */
	public Route[] getRoutes();

}
