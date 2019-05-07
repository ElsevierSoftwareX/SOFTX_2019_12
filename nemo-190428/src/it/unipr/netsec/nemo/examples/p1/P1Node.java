package it.unipr.netsec.nemo.examples.p1;


import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Node;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.nemo.link.DataLink;
import it.unipr.netsec.nemo.link.DataLinkInterface;


/** Node implementing protocol P1.
 * <p>
 * Nodes are interconnected in nxm network.
 * Hence, each node has 4 network interfaces: norther, easter, souther, and western interface.
 * <p>
 * Routing is performed accordingly to this network topology.
 */
public class P1Node extends Node {

	/** Creates a new node.
	 * @param addr the node address
	 * @param north norther link
	 * @param east easter link
	 * @param south souther link
	 * @param west wester link */
	public P1Node(P1Address addr, DataLink north, DataLink east, DataLink south, DataLink west) {
		super(createNetInterfaces(addr,north,east,south,west),null,true);
		setRouting(new P1RoutingFunction(addr,getNetInterfaces()));
	}
	
	@Override
	protected void processReceivedPacket(NetInterface ni, Packet pkt) {
		if (hasAddress(pkt.getDestAddress())) System.out.println("Node "+this.getNetInterfaces()[0].getAddresses()[0]+" received packet: "+pkt);
		else processForwardingPacket(pkt);
	}
	
	private static NetInterface[] createNetInterfaces(P1Address addr, DataLink north, DataLink east, DataLink south, DataLink west) {
		NetInterface[] ni=new NetInterface[4];
		ni[0]=new DataLinkInterface(north,addr);
		ni[1]=new DataLinkInterface(east,addr);
		ni[2]=new DataLinkInterface(south,addr);
		ni[3]=new DataLinkInterface(west,addr);
		return ni;
	}

}
