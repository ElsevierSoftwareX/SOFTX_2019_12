package it.unipr.netsec.nemo.routing;


import java.util.ArrayList;
import java.util.Hashtable;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.nemo.routing.graph.Edge;
import it.unipr.netsec.nemo.routing.graph.Graph;
import it.unipr.netsec.nemo.routing.graph.Node;
import it.unipr.netsec.nemo.routing.graph.Path;


/** Simple-graph specified through the adjacency matrix.
 *  <p>
 *  It provides methods for converting {@link it.unipr.netsec.nemo.routing.graph.Graph} objects to node indexes and vice-versa. 
 */
class SimpleGraph {

	/** Debug mode */
	public static boolean DEBUG=false;
	
	/** Prints a debug message. */
	private static void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,SimpleGraph.class,str);
	}

	
	/** Simple-graph adjacency */
	boolean[][] adjacent;

	/** Graph nodes (they are present only for mapping graph nodes to node indexes and vice-versa */
	Node[] nodes;

	/** graph edges (they are present only for returning the shortest-path as sequence of graph edges) */
	Edge[][] edges;

	
	/** Creates a simple-graph. 
	 * It converts a {@link it.unipr.netsec.nemo.routing.graph.Graph} to a adjacency matrix of a simple-graph.
	 * @param g the graph */
	public SimpleGraph(Graph g) {
		if (DEBUG) debug("SimpleGraph(): converting a graph to a simple graph");
		nodes=g.getNodes().toArray(new Node[]{});
		int N=nodes.length;
		adjacent=new boolean[N][N];
		edges=new Edge[N][N];
		for (int i=0; i<N; i++) for (int j=0; j<N; j++) {
			adjacent[i][j]=g.hasEdge(nodes[i],nodes[j]);
			if (adjacent[i][j]) edges[i][j]=g.getEdges(nodes[i],nodes[j]).iterator().next();
		}
	}
	
	/** Gets the adjacency matrix. 
	 * @return the matrix */
	public boolean[][] getAdjacency() {
		return adjacent;
	}
	
	/** Gets the index of a given node. 
	 * @param node the node
	 * @return the index of the node */
	public int getNodeIndex(Node node) {
		int i=0;
		while (!nodes[i].equals(node)) i++;				
		return i;
	}
	
	/** Gets a node
	 * @param index the node index
	 * @return the node */
	public Node getNode(int index) {
		return nodes[index];
	}
	
	/** Gets the specified paths
	 * @param s the index of the source node of the paths
	 * @param p array of paths specified as sequence of node indexes
	 * @return a table of destinations and paths */
	public Hashtable<Node,Path> getPaths(int s, ArrayList<Integer>[] p) {
		Hashtable<Node,Path> paths=new Hashtable<Node,Path>();
		int N=nodes.length;
		for (int i=0; i<N; i++) {
			if (p[i]!=null) {
				Node dst=nodes[i];
				Path path=new Path(nodes[s]);
				for (int j=1; j<p[i].size(); j++) {
					path.add(edges[p[i].get(j-1)][p[i].get(j)]); 
				}
				paths.put(dst,path);
			}
		}
		return paths;
	}
	
}
