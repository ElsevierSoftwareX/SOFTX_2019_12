package it.unipr.netsec.nemo.examples;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.nemo.ip.Ip4Host;
import it.unipr.netsec.nemo.ip.Ip4Router;
import it.unipr.netsec.nemo.ip.IpLink;


/** IPv4 network with two links and one router.
 * <p>
 * Two hosts H1 and H2 are connected to the two access links link1 and link2
 * interconnected through intermediate router R1. H1 pings H2.
 * <p>
 * Network topology:
 * <p>
 * <center> H1---(link1)---R1---(link2)---H2 </center>
 */
public class SimpleIPv4NetworkExample {

	public static void main(String[] args) {
		long bit_rate=1000000; // 1Mb/s
		IpLink link1=new IpLink(bit_rate,new Ip4Prefix("10.1.0.0/16"));
		IpLink link2=new IpLink(bit_rate,new Ip4Prefix("10.2.0.0/16"));
		
		Ip4Router r1=new Ip4Router(new IpLink[]{link1,link2});
		System.out.println("R1-RT:\n"+r1.getRoutingTable());

		Ip4Host host1=new Ip4Host(link1);		
		System.out.println("H1-RT:\n"+host1.getRoutingTable());
		
		Ip4Host host2=new Ip4Host(link2);
		System.out.println("H2-RT:\n"+host2.getRoutingTable());
		
		host1.ping((Ip4Address)host2.getAddress(),3,System.out);
	}

}
