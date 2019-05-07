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


//import it.unipr.netsec.nemo.routing.sdn.PathInfo;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** Collection of static methods for managing Graphs.
 */
public class GraphUtils {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private static void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,GraphUtils.class,str);
	}

	/** No default constructor. */
	private GraphUtils() {
	}

	/** Gets the shortest paths from a given node to all nodes
	 * <p>
	 * It uses the Dijkstra algorithm for minimum path computation.
	 * @param g network graph
	 * @param src the source node
	 * @return a table with the shortest paths toward all nodes */
	public static Hashtable<Node,Path> dijkstra(Graph g, Node src) {
		if (DEBUG) debug("dijkstra()");
		Collection<Node> nodes=g.getNodes();
		Hashtable<Node,Path> paths=new Hashtable<Node,Path>(); // paths from src to each graph node
		int INFINITY=Integer.MAX_VALUE;
		paths.put(src,new Path(src));
		HashSet<Node> visited=new HashSet<Node>();
		if (DEBUG) debug("dijkstra(): all nodes: "+nodes);
		do {
			if (DEBUG) debug("dijkstra(): src: "+src);
			visited.add(src);
			Node nearest=null;
			int minimum_distance=INFINITY;
			for (Node nxt: nodes) {
				if (!visited.contains(nxt)) {
					Collection<Edge> adj_edges=g.getEdges(src,nxt);
					if (DEBUG) debug("dijkstra(): edges("+src+","+nxt+"): "+adj_edges);
					for (Edge edge: adj_edges) {
						int dist_src=paths.containsKey(src)? paths.get(src).length()+1 : INFINITY;
						int dist_nxt=paths.containsKey(nxt)? paths.get(nxt).length() : INFINITY;
						if (dist_nxt>=dist_src) {
							Path new_path=new Path(paths.get(src));
							new_path.add(edge);
							paths.put(nxt,new_path);
						}
					}
					int dist=paths.containsKey(nxt)? paths.get(nxt).length() : INFINITY;
					if (dist<minimum_distance) {
						minimum_distance=dist;
						nearest=nxt;
					}
				}
			}			
			if (DEBUG) debug("dijkstra(): src="+src+", nearest="+nearest+", dist="+minimum_distance);
			src=nearest;
		}
		while (src!=null);
		return paths;
	}

	
	/** Gets the shortest paths from all nodes to all nodes
	 * <p>
	 * It uses the Floyd–Warshall algorithm for minimum path computation.
	 * @param g network graph
	 * @return a table M={(a,Ta), (b,Tb), .. ,(z,Tz)} of pair (s,Ts) where Ts is
	 *         a table Ts={(a,Psa), (b,Psb), .. (zPsz)}, where Pst is the shortest path from s to t */
	public static Hashtable<Node,Hashtable<Node,Path>> floydWarshall(Graph g) {
		if (DEBUG) debug("floydWarshall()");
		Collection<Node> nodes=g.getNodes();
		Hashtable<Node,Hashtable<Node,Path>> shortest_paths=new Hashtable<Node,Hashtable<Node,Path>>();		
		for (Node i: nodes) {
			Hashtable<Node,Path> sp_i=new Hashtable<Node,Path>();
			shortest_paths.put(i,sp_i);
			for (Node j: nodes) {
				if (i.equals(j)) sp_i.put(j,new Path(i));
				else
					if (g.hasEdge(i,j)) sp_i.put(j,new Path(new Edge[]{g.getEdges(i,j).iterator().next()}));
			}
		}
		for (Node k: nodes) {
			for (Node i: nodes) {
				for (Node j: nodes) {
					Path sp_ik=shortest_paths.get(i).get(k);
					if (sp_ik!=null) {
						Path sp_kj=shortest_paths.get(k).get(j);
						if (sp_kj!=null) {
							Path sp_ij=shortest_paths.get(i).get(j);
							if (sp_ij==null || sp_ij.length()>(sp_ik.length()+sp_kj.length())) {
								sp_ij=new Path(sp_ik);
								sp_ij.append(sp_kj);
								shortest_paths.get(i).put(j,sp_ij);
							}
						}
					}
				}
			}
		}
		return shortest_paths;
	}

	
	/** Gets the shortest paths from all nodes to all nodes
	 * <p>
	 * It uses the Bellman-Ford algorithm for minimum path computation.
	 * @param g network graph
	 * @return a table M={(a,Ta), (b,Tb), .. ,(z,Tz)} of pair (s,Ts) where Ts is
	 *         a table Ts={(a,Psa), (b,Psb), .. (zPsz)}, where Pst is the shortest path from s to t */
	public static Hashtable<Node,Hashtable<Node,Path>> bellmanFord(Graph g) {
		if (DEBUG) debug("bellmanFord()");
		Collection<Node> nodes=g.getNodes();
		Hashtable<Node,Hashtable<Node,Path>> shortest_paths=new Hashtable<Node,Hashtable<Node,Path>>();		
		HashSet<Node> changed_nodes=new HashSet<Node>();
		for (Node i: nodes) {
			Hashtable<Node,Path> sp_i=new Hashtable<Node,Path>();
			shortest_paths.put(i,sp_i);
			for (Node j: nodes) {
				if (i.equals(j)) sp_i.put(j,new Path(i));
				else
					if (g.hasEdge(i,j)) sp_i.put(j,new Path(new Edge[]{g.getEdges(i,j).iterator().next()}));
			}
			changed_nodes.add(i);
		}
		HashSet<Node> new_changed_nodes=new HashSet<Node>();
		boolean changed=true;
		while (changed) {
			changed=false;
			for (Node i: nodes) {
				if (DEBUG) debug("bellmanFord(): i="+i);
				boolean changed_i=false;
				Hashtable<Node,Path> sp_i=shortest_paths.get(i);				
				for (Edge e_ik: g.getEdges(i)) {
					Node k=e_ik.getDestNode();
					if (changed_nodes.contains(k)) {
						if (DEBUG) debug("bellmanFord(): k="+k);
						Hashtable<Node,Path> sp_k=shortest_paths.get(k);
						if (DEBUG) debug("bellmanFord(): sp_k="+sp_k.toString());
						for (Node j: sp_k.keySet()) {
							Path sp_kj=sp_k.get(j);
							if (sp_i.containsKey(j)) {
								Path sp_ij=sp_i.get(j);
								if (DEBUG) debug("bellmanFord(): sp_ij="+sp_ij.toString());
								if (sp_ij.length()>(sp_kj.length()+1)) {
									sp_ij=new Path(i);
									sp_ij.add(e_ik);
									sp_ij.append(sp_kj);
									sp_i.put(j,sp_ij);
									changed_i=true;
									if (DEBUG) debug("bellmanFord(): new sp_ij="+sp_ij.toString());
								}
							}		
							else {
								Path sp_ij=new Path(i);
								sp_ij.add(e_ik);
								sp_ij.append(sp_kj);
								sp_i.put(j,sp_ij);
								changed_i=true;
								if (DEBUG) debug("bellmanFord(): new sp_ij="+sp_ij.toString());
							}
						}						
					}
				}
				if (changed_i) {
					changed=true;
					new_changed_nodes.add(i);
				}
			}
			HashSet<Node> temp=changed_nodes;
			changed_nodes=new_changed_nodes;
			new_changed_nodes=temp;
			new_changed_nodes.clear();
		}		
		return shortest_paths;
	}

	
	/** Gets the shortest paths from a given node to all nodes
	 * <p>
	 * It uses the Dijkstra algorithm for minimum path computation.
	 * @param adjacent adjacency matrix
	 * @param s the source node
	 * @return an array of shortest paths toward all nodes */
	public static ArrayList<Integer>[] dijkstra(boolean[][] adjacent, int s) {
		if (DEBUG) debug("dijkstra(boolean[][],int)");
		int N=adjacent.length;		
		int INFINITY=Integer.MAX_VALUE;
		ArrayList<Integer>[] p=(ArrayList<Integer>[])new ArrayList[N];
		int u=s;
		p[u]=new ArrayList<Integer>();
		p[u].add(u);
		boolean[] visited=new boolean[N];
		Arrays.fill(visited,false);		
		do {
			if (DEBUG) debug("dijkstra(): u: "+u);
			visited[u]=true;
			int nearest=-1;
			int minimum_distance=INFINITY;
			for (int v=0; v<N; v++) {
				if (!visited[v]) {
					if (adjacent[u][v]) {
						if (DEBUG) debug("dijkstra(): edge ("+u+","+v+")");					
						int dist_u=p[u]!=null? p[u].size()+1 : INFINITY;
						int dist_v=p[v]!=null? p[v].size() : INFINITY;
						if (dist_v>=dist_u) {
							ArrayList<Integer> path_v=new ArrayList<Integer>(p[u]);
							path_v.add(new Integer(v));
							p[v]=path_v;
						}
					}
					int dist=p[v]!=null? p[v].size() : INFINITY;
					if (dist<minimum_distance) {
						minimum_distance=dist;
						nearest=v;
					}
				}
			}			
			if (DEBUG) debug("dijkstra(): u="+u+", nearest="+nearest+", dist="+minimum_distance+", path="+Arrays.asList(p[u]).toString());
			u=nearest;
		}
		while (u>=0);
		return p;
	}

}
