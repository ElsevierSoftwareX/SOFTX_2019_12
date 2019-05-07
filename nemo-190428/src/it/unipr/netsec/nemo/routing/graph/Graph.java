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


import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;


/** Directed graph.
 */
public class Graph {

	/** Graph edges (HashSet<edge>) */
	HashSet<Edge> edges=new HashSet<Edge>();

	/** Graph nodes (Hashtable<node_id,node>) */
	Hashtable<String,Node> nodes=new Hashtable<String,Node>();

	/** Source nodes to edges (Hashtable<src,HashSet<edge>>) */
	Hashtable<Node,HashSet<Edge>> node_to_edges=new Hashtable<Node,HashSet<Edge>>();

	
	/** Creates a new Graph. */
	public Graph() {
	}

	/** Adds a new node.
	 * @param node the new node */
	public synchronized void addNode(Node node) {
		String id=node.getId();
		if (!nodes.containsKey(id)) {
			nodes.put(id,node);
			node_to_edges.put(node,new HashSet<Edge>());
		}
	}
	
	/** Adds a new edge.
	 * @param edge the new edge */
	public synchronized void addEdge(Edge edge) {
		Node src=edge.getSourceNode();
		Node dst=edge.getDestNode();
		addNode(src);
		addNode(dst);
		node_to_edges.get(src).add(edge);
		edges.add(edge);
	}
	
	/** Gets all nodes.
	 * @return all nodes */
	public synchronized Collection<Node> getNodes() {
		return nodes.values();
	}

	/** Gets all edges.
	 * @return all edges */
	public synchronized Collection<Edge> getEdges() {
		return edges;
	}

	/** Gets a node with a given id.
	 * @param id node id
	 * @return the node */
	public synchronized Node getNode(String id) {
		return nodes.get(id);
	}

	/** Gets edges from a given node.
	 * @param src the edge source node
	 * @return the edges */
	public synchronized Collection<Edge> getEdges(Node src) {
		return node_to_edges.get(src);
	}

	/** Gets edges between a pair of adjacent nodes.
	 * @param src the source node
	 * @param dst the destination node
	 * @return the edges */
	public synchronized Collection<Edge> getEdges(Node src, Node dst) {
		HashSet<Edge> adj_edges=new HashSet<Edge>();
		HashSet<Edge> src_edges=node_to_edges.get(src);
		for (Edge edge: src_edges) {
			if (edge.getDestNode().equals(dst)) adj_edges.add(edge);
		}
		return adj_edges;
	}

	/** Whether there is an edge between two nodes.
	 * @param src the source node
	 * @param dst the destination node
	 * @return <i>true</i> if the two nodes are directly connected */
	public synchronized boolean hasEdge(Node src, Node dst) {
		HashSet<Edge> src_edges=node_to_edges.get(src);
		for (Edge edge: src_edges) {
			if (edge.getDestNode().equals(dst)) return true;
		}
		return false;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof Graph)) return false;
		// else
		Graph g=(Graph)o;
		if (nodes.size()!=g.nodes.size() || edges.size()!=g.edges.size()) return false;
		// else
		Collection<Node> g_nodes=g.nodes.values();
		for (Node n: nodes.values()) if (!g_nodes.contains(n)) return false;
		// else
		for (Edge e: edges) if (!g.edges.contains(e)) return false;
		// else
		return true;
	}

	@Override
	public void finalize() {
		nodes.clear();
		edges.clear();
		node_to_edges.clear();
	}
	
	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append('{');
		boolean first_edge=true;
		for (Edge edge : edges) {
			if (first_edge) first_edge=false; else sb.append(", ");
			sb.append(edge);
		}
		sb.append('}');
		return sb.toString();
	}
}
