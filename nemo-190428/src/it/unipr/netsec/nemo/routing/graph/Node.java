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

package it.unipr.netsec.nemo.routing.graph;



/** Node.
 */
public class Node implements Comparable<Node> {

	/** Node id */
	String id;
	
	/** Creates a new node.
	 * @param id node id */
	public Node(String id) {
		this.id=id;
	}
	
	/** Gets node id.
	 * @return the id */
	public String getId() {
		return id;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Node)) return false;
		// else
		Node n=(Node)obj;
		return id.equals(n.id);
	}
	
	@Override
	public int compareTo(Node node) {
		return id.compareTo(node.id);
	}
	
	@Override
	public String toString() {
		return id;
	}
	
}
