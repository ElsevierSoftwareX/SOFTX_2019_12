package it.unipr.netsec.nemo.examples;


import it.unipr.netsec.ipstack.analyzer.ProtocolAnalyzer;
import it.unipr.netsec.ipstack.analyzer.Sniffer;
import it.unipr.netsec.ipstack.analyzer.SnifferListener;
import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.nemo.ip.Ip4Host;
import it.unipr.netsec.nemo.ip.Ip4Router;
import it.unipr.netsec.nemo.ip.IpLink;
import it.unipr.netsec.nemo.link.PromiscuousLinkInterface;


public class SnifferExample {

	public static void main(String[] args) {
		long bit_rate=1000000; // 1Mb/s
		IpLink link1=new IpLink(bit_rate,new Ip4Prefix("10.1.1.0/24"));
		IpLink link2=new IpLink(bit_rate,new Ip4Prefix("10.2.2.0/24"));
		
		Ip4Router r1=new Ip4Router(new IpLink[]{link1,link2});
		Ip4Host host1=new Ip4Host(link1);				
		Ip4Host host2=new Ip4Host(link2);
		
		// capture all packets sent through link1
		new Sniffer(new PromiscuousLinkInterface(link1), new SnifferListener(){
			@Override
			public void onPacket(Sniffer sniffer, NetInterface ni, Packet pkt) {
				System.out.println("Captured packet: "+ProtocolAnalyzer.exploreInner(pkt));
			}			
		});

		host1.ping((Ip4Address)host2.getAddress(),3,System.out);	
	}

}
