package it.unipr.netsec.tuntap;


import java.io.IOException;

import it.unipr.netsec.ipstack.ethernet.EthAddress;
import it.unipr.netsec.ipstack.ethernet.EthInterface;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4EthInterface;


/** TAP interface for sending or receiving Ethernet packets.
 */
public class Ip4TapInterface extends Ip4EthInterface {
	
	static EthAddress ETH_ADDR=new EthAddress("11:22:33:44:55:66");

	
	/** Creates a new interface.
	 * @param name name of the interface (e.g. "tap0"); if <i>null</i>, a new interface is added
	 * @param ip_addr_prefix the IP address and prefix length 
	 * @throws IOException */
	public Ip4TapInterface(String name, Ip4AddressPrefix ip_addr_prefix) throws IOException {
		super(new EthInterface(new TapInterface(name),ETH_ADDR),ip_addr_prefix);
	}

}
