package it.unipr.netsec.nemo.routing;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.nemo.routing.graph.Edge;
import it.unipr.netsec.nemo.routing.graph.Graph;
import it.unipr.netsec.nemo.routing.graph.GraphUtils;
import it.unipr.netsec.nemo.routing.graph.Node;
import it.unipr.netsec.nemo.routing.graph.Path;


/** It creates the network graph based on LS information and computes the shortest-paths.
 * <p>
 * Different shortest-path algorithms are supported:
 * <ul>
 * <li>Dijkstra;</li>
 * <li>Alternative Dijkstra implementation with simple graphs</li>
 * <li>Bellman-Ford;</li>
 * <li>Floyd-Warshall.</li>
 * </ul>
 */
public class NetworkMap {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private static void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,NetworkMap.class,str);
	}
		
	
	/** Shortest-path algorithm */
	ShortestPathAlgorithm algo;
	
	/** Set of network nodes. it is used for distinguish network nodes from links amongst the nodes of the modified graph */
	HashSet<String> nodes=new HashSet<>();
	
	/** Network graph */
	Graph g=new Graph();
	
	/** Whether graph has been changed */
	boolean graph_changed=false;

	
	/** Shortest paths from all sources (table key) to all possible destinations */
	Hashtable<Node,Hashtable<Node,Path>> all_shortest_paths=null;

	/** Simple graph (used by the alternative Dijkstra simple implementation) */
	SimpleGraph simple_graph=null;

	
	
	public NetworkMap(ShortestPathAlgorithm algo) {
		this.algo=algo;
	}

	/** Resets network graph. */
	public void clear() {
		g=new Graph();
		if (all_shortest_paths!=null) all_shortest_paths.clear();
		graph_changed=false;
	}

	/** Gets the network graph.
	 * @return the network graph */
	public Graph getNetworkGraph() {
		return g;
	}

	/** Adds a LS.
	 * @param node_addr the LS node
	 * @param link_state the LS */
	public void addLikState(Address node_addr, LinkStateInfo[] link_state) {
		String node_id=node_addr.toString();
		synchronized(g) {
			if (g.getNode(node_id)!=null) throw new RuntimeException("node '"+node_id+"' already exists in the network graph");
			// else
			nodes.add(node_id);
			Node node=new Node(node_id);
			g.addNode(node);
			for (LinkStateInfo lsi: link_state) {
				String addr=lsi.getAddress().toString();
				String prefix=lsi.getPrefix().toString();
				if (g.getNode(prefix)==null) g.addNode(new Node(prefix));
				g.addEdge(new Edge(g.getNode(node_id),g.getNode(prefix),addr));
				g.addEdge(new Edge(g.getNode(prefix),g.getNode(node_id),addr));
			}
			graph_changed=true;			
		}
	}
	
	/** Removes a LS.
	 * @param node_addr the LS node */
	public void removeLinkState(Address node_addr) {
		// remove node and edges from the graph
		// TODO
	}

	/** Gets route information from a given source node toward all possible destinations.
	 * @param src_addr the source node address
	 * @return array of routes */
	public RouteInfo[] getRoutes(Address src_addr) {		
		Node src_node=g.getNode(src_addr.toString());
		// shortest paths
		Hashtable<Node,Path> paths=null;
		synchronized(g) {
			if (algo==ShortestPathAlgorithm.DIJKSTRA || algo==ShortestPathAlgorithm.DIJKSTRA_SIMPLE) {
				if (all_shortest_paths==null || graph_changed) {
					all_shortest_paths=new Hashtable<>();
					graph_changed=false;
				}
				if (!all_shortest_paths.containsKey(src_node)) {
					if (algo==ShortestPathAlgorithm.DIJKSTRA) {
						all_shortest_paths.put(src_node,GraphUtils.dijkstra(g,src_node));
					}
					else {
						if (DEBUG) debug(algo.toString()+": converting to simple-graph");
						simple_graph=new SimpleGraph(g);
						int s=simple_graph.getNodeIndex(src_node);
						ArrayList<Integer>[] p=GraphUtils.dijkstra(simple_graph.getAdjacency(),s);
						all_shortest_paths.put(src_node,simple_graph.getPaths(s,p));
					}
				}
				paths=all_shortest_paths.get(src_node);
			}
			else
			if (algo==ShortestPathAlgorithm.FLOYD_WARSHALL) {
				if (all_shortest_paths==null || graph_changed) {
					if (DEBUG) debug(algo.toString()+" pre-conversion");
					all_shortest_paths=GraphUtils.floydWarshall(g);
					graph_changed=false;
				}
				paths=all_shortest_paths.get(src_node);
			}
			else
			if (algo==ShortestPathAlgorithm.BELLMAN_FORD) {
				if (all_shortest_paths==null || graph_changed) {
					if (DEBUG) debug(algo.toString()+" pre-conversion");
					all_shortest_paths=GraphUtils.bellmanFord(g);
					graph_changed=false;
				}
				paths=all_shortest_paths.get(src_node);
			}
			else {
				throw new RuntimeException("Unsupported shortest-path algorithm: "+algo);
			}
		}
		// routes		
		ArrayList<RouteInfo> routes=new ArrayList<RouteInfo>();		
		for (Node dest_i: paths.keySet()) {
			// check if it is a network node
			if (nodes.contains(dest_i.getId())) continue;
			// else
			Path path=paths.get(dest_i);
			if (path.size()>1) {
				String net_interface=path.getEdgePath().get(0).getValue();
				String next_hop=path.size()>2? path.getEdgePath().get(1).getValue() : null;
				String dest=dest_i.getId();
				routes.add(new RouteInfo(dest,next_hop,net_interface,1));
			}			
		}
		if (DEBUG) debug("getRoutes("+src_addr+"): "+routes);
		return routes.toArray(new RouteInfo[]{});			
	}

}
