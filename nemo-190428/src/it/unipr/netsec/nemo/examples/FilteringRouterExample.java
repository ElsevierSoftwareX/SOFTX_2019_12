package it.unipr.netsec.nemo.examples;


import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.nemo.ip.Ip4Host;
import it.unipr.netsec.nemo.ip.IpLink;


/** IPv4 network with two links connected through a packet filtering (PF) router.
 * <p>
 * <center>
 * H1---(link1)---PF---(link2)---H2
 * </center>
 * <p>
 * H1 pings H2.
 * During the ping, H2 address is filtered for a while by the PF router.
 */
public class FilteringRouterExample {

	public static void main(String[] args) {
		boolean verbose=true;
		if (verbose) SystemUtils.setDefaultLogger(new LoggerWriter(System.out));
		
		long bit_rate=1000000; // 1Mb/s
		IpLink link1=new IpLink(bit_rate,new Ip4Prefix("10.1.0.0/24"));
		IpLink link2=new IpLink(bit_rate,new Ip4Prefix("10.1.1.0/24"));
		
		FilteringRouter pf=new FilteringRouter(new IpLink[]{link1,link2},FilteringRouter.Action.ACCEPT);

		Ip4Host host1=new Ip4Host(link1);				
		Ip4Host host2=new Ip4Host(link2);
		
		System.out.println("From H1 ("+host1.getAddress()+") pinging H2 ("+host2.getAddress()+")");
		host1.ping((Ip4Address)host2.getAddress(),10,System.out);
		
		SystemUtils.sleep(3000);
		System.out.println("start filtering H2");
		pf.add(new Ip4Prefix(host2.getAddress(),32));

		SystemUtils.sleep(3000);
		System.out.println("stop filtering H2");
		pf.remove(new Ip4Prefix(host2.getAddress(),32));
	}

}
