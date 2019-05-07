package it.unipr.netsec.nemo.routing;



/** Shortest-path algorithm.
 * <p>
 * It only defines the type of the shortest-path algorithm.
 */
public class ShortestPathAlgorithm {

	/** Algorithm name */
	private String name;

	/** Creates an algorithm type
	 * @param name the name of the algorithm */
	private ShortestPathAlgorithm(String name) { this.name=name; }

	@Override
	public String toString() { return name; }

	
	/** Dijkstra algorithm */
	public static final ShortestPathAlgorithm DIJKSTRA=new ShortestPathAlgorithm("Dijkstra");

	/** Dijkstra algorithm with simple graph */
	public static final ShortestPathAlgorithm DIJKSTRA_SIMPLE=new ShortestPathAlgorithm("Dijkstra (with simple graph)");	
	
	/** Bellman-Ford algorithm */
	public static final ShortestPathAlgorithm BELLMAN_FORD=new ShortestPathAlgorithm("Bellman-Ford");

	/** Floyd-Warshall algorithm */
	public static final ShortestPathAlgorithm FLOYD_WARSHALL=new ShortestPathAlgorithm("Floyd-Warshall");

}
