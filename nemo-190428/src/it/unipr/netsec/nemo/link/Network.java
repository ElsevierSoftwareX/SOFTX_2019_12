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

package it.unipr.netsec.nemo.link;

import java.util.Arrays;

import it.unipr.netsec.ipstack.link.Link;
import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;


/** It is a set of nodes connected through links. 
 */
public class Network {

	/** Name */
	//String name;

	/** Access links */
	Link[] access_links;
	
	/** Core links */
	Link[] core_links;

	/** Network nodes */
	Node[] nodes;

	
	/** Creates a new network.
	 * @param nodes network nodes
	 * @param links network links */
	public Network(Node[] nodes, Link[] links) {
		this(nodes,links,null);
	}

	/** Creates a new network.
	 * @param nodes network nodes
	 * @param access_links access links
	 * @param core_links core links */
	public Network(Node[] nodes, Link[] access_links, Link[] core_links) {
		this.access_links=access_links;
		this.core_links=core_links;
		this.nodes=nodes;
	}

	/** Returns the network name. */
	/*public String getName() {
		return name;
	}*/
	
	/** Returns the network links. */
	public Link[] getAccessLinks() {
		return access_links;
	}
	
	/** Returns the network links. */
	public Link[] getCoreLinks() {
		return core_links;
	}
	
	/** Returns the network nodes. */
	public Node[] getNodes() {
		return nodes;
	}
	
	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		//sb.append(Arrays.toString(nodes));
		sb.append('[');
		for (int i=0; i<nodes.length; i++) {
			if (i>0) sb.append(", ");
			sb.append(nodes[i]).append('[');
			NetInterface[] ni=nodes[i].getNetInterfaces();
			for (int j=0; j<ni.length; j++) {
				if (j>0) sb.append(',');
				Address[] addr=ni[j].getAddresses();
				sb.append(addr.length>0? addr[0] : "null");
			}
			sb.append(']');
		}
		sb.append(']');
		sb.append(access_links!=null? Arrays.toString(access_links) : "[]");
		sb.append(core_links!=null? Arrays.toString(core_links) : "[]");
		return sb.toString();
	}
}
