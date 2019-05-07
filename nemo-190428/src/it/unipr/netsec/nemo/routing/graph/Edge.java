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




/** Directed edge.
 */
public class Edge implements Comparable<Edge> {

	/** Source node */
	Node src;

	/** Destination node */
	Node dst;

	/** Edge value */
	String val=null;
	

	/** Creates a new edge.
	 * @param src root node
	 * @param dst destination node */
	public Edge(Node src, Node dst) {
		this.src=src;
		this.dst=dst;
	}
	
	/** Creates a new edge.
	 * @param src root node
	 * @param dst destination node
	 * @param val edge value */
	public Edge(Node src, Node dst, String val) {
		this.src=src;
		this.dst=dst;
		this.val=val;
	}
	
	/** Gets source node.
	 * @return the source node */
	public Node getSourceNode() {
		return src;
	}
	
	/** Gets destination node.
	 * @return the destination node */
	public Node getDestNode() {
		return dst;
	}
	
	/** Gets edge value.
	 * @return the value */
	public String getValue() {
		return val;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Edge)) return false;
		// else
		Edge e=(Edge)obj;
		return src.equals(e.src) && dst.equals(e.dst) && (val!=null? val.equals(e.val) : true);
	}
	
	@Override
	public int compareTo(Edge e) {
		int res=src.compareTo(e.src);
		if (res==0) res=dst.compareTo(e.dst);
		if (res==0 && val!=null && e.val!=null) res=val.compareTo(e.val);
		return res;
	}
	
	@Override
	public String toString() {
		return "("+src+","+dst+(val!=null?";"+val:"")+")";
	}
	
}
