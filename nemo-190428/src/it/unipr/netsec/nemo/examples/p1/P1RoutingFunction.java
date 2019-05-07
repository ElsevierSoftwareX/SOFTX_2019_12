package it.unipr.netsec.nemo.examples.p1;


import it.unipr.netsec.ipstack.net.Address;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.routing.Route;
import it.unipr.netsec.ipstack.routing.RoutingFunction;


/** Routing function in a nxm network.
 */
class P1RoutingFunction implements RoutingFunction {
	
	int i;
	int j;
	NetInterface[] ni; // north, east, south, west
	
	/** Creates a new routing function.
	 * @param addr the node address
	 * @param ni the network interfaces */
	public P1RoutingFunction(P1Address addr, NetInterface[] ni) {
		this.i=addr.getI();
		this.j=addr.getJ();
		this.ni=ni;
	}
	
	@Override
	public Route getRoute(Address dest_addr) {
		P1Address d=(P1Address)dest_addr;
		int di=d.getI();
		int dj=d.getJ();
		if (i<di) return new Route(null,new P1Address(i+1,j),ni[2]); // -> south
			else if (i>di) return new Route(null,new P1Address(i-1,j),ni[0]); // -> north
				else if (j<dj) return new Route(null,new P1Address(i,j+1),ni[1]); // -> east
					else if (j>dj) return new Route(null,new P1Address(i,j-1),ni[3]); // -> west
						else return null;
	}
}

