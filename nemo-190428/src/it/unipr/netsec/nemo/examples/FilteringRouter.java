package it.unipr.netsec.nemo.examples;


import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4Packet;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.net.NetInterface;
import it.unipr.netsec.ipstack.net.Packet;
import it.unipr.netsec.nemo.ip.Ip4Router;
import it.unipr.netsec.nemo.ip.IpLink;

import java.util.ArrayList;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** Example of an IPv4 packet filtering router.
 * <p>
 * It filters packets based on their destination addresses. It may work with either an
 * <code>ACCEPT</code> or <code>DROP</code> default policy.
 * <p>
 * If the default policy is <code>ACCEPT</code> then the filter rules in the ACL specify the target addresses to be dropped.
 * If the default policy is <code>DROP</code> then the filter rules specify the target addresses to be accepted.
 */
public class FilteringRouter extends Ip4Router {

	/** Prints a log message. */
	private void printLog(String str) {
		SystemUtils.log(LoggerLevel.INFO,FilteringRouter.class,str);
	}
	
	
	/** Possible ACL actions. */
	public enum Action {
	    ACCEPT, DROP 
	}
	
	/** Default policy */
	Action default_policy;
	
	/** Access control list */
	ArrayList<Ip4Prefix> acl=new ArrayList<>();
	

	/** Creates a new filtering router.
	 * @param ip_links the IP links the router is attached to
	 * @param default_policy the default filtering policy */
	public FilteringRouter(IpLink[] ip_links, Action default_policy) {
		super(ip_links);
		this.default_policy=default_policy;
	}

	/** Creates a new filtering router
	 * @param default_policy the default filtering policy
	 * @param net_interfaces the network interfaces */
	public FilteringRouter(NetInterface[] net_interfaces, Action default_policy) {
		super(net_interfaces);
		this.default_policy=default_policy;
	}

	@Override
	protected void processForwardingPacket(Packet pkt) {
		Ip4Packet ip_pkt=(Ip4Packet)pkt;
		Ip4Address dst_addr=(Ip4Address)ip_pkt.getDestAddress();
		boolean matched=false;
		for (Ip4Prefix mathcing_rule : acl) {
			matched=mathcing_rule.contains(dst_addr);
			if (matched) break;
		}
		boolean accept=(default_policy.equals(Action.ACCEPT) && !matched) || (default_policy.equals(Action.DROP) && matched);
		if (accept) super.processForwardingPacket(pkt);
		else {
			printLog("packet dropped: "+pkt.toString());
		}	
	}

	/** Adds a filtering rule.
	 * @param dst_prefix destination network address to be matched */
	public void add(Ip4Prefix dst_prefix) {
		acl.add(dst_prefix);
	}

	/** Removes a filtering rule.
	 * @param dst_prefix destination network address */
	public void remove(Ip4Prefix dst_prefix) {
		acl.remove(dst_prefix);
	}

}
