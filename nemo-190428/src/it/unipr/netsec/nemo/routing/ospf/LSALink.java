package it.unipr.netsec.nemo.routing.ospf;

import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;
import it.unipr.netsec.ipstack.ip4.Ip4AddressPrefix;
import it.unipr.netsec.ipstack.ip4.Ip4Prefix;
import it.unipr.netsec.ipstack.util.IpAddressUtils;


/** LSA link field, describing a router link.
 */
public class LSALink {

	/** Type Point-to-point connection to another router */
	public static final int TYPE_PTPT=1;
	
	/** Type Connection to a transit network */
	public static final int TYPE_TRANSIT=2;
	
	/** Type Connection to a stub network */
	public static final int TYPE_STUB=3;
	
	/** Type Virtual link */
	public static final int TYPE_VIRTUAL=4;
	

	/** Link type */
	int type;
	
	/** Link ID */
	//Ip4Prefix link_id; 

	/** Link Data */
	//Ip4Address link_data; 

	/** Link address and prefix */
	Ip4AddressPrefix link_addr_prefix; 

	/** Number of different TOS metrics */
	//long tos_num; 

	/** Metric */
	int metric; 

	/** TOS */
	int[] tos=null; 

	/** TOS metric */
	int[] tos_metric; 

	
	/** Creates a new link field.
	 * @param type link type
	 * @param link_addr_prefix link address and prefix length
	 * @param metric link cost */
	public LSALink(int type, Ip4AddressPrefix link_addr_prefix, int metric) {
		this.type=type;
		this.link_addr_prefix=link_addr_prefix;
		this.metric=metric;
	}
	
	/** Creates a link field.
	 * @param buf buffer containing the link field
	 * @param off offset of the link field within the buffer */
	public LSALink(byte[] buf, int off) {
		this(0xff&buf[off+8],new Ip4AddressPrefix(buf,off,IpAddressUtils.maskToPrefixLength(buf,off+4)),ByteUtils.twoBytesToInt(buf,off+10));
		int tos_num=0xff&buf[off+9];
		if (tos_num>0) {
			tos=new int[tos_num];
			tos_metric=new int[tos_num];
		}
		for (int i=0; i<tos_num; i++) {
			tos[i]=0xff&buf[off+12+i*4];
			tos_metric[i]=ByteUtils.twoBytesToInt(buf,off+14+i*4);
		}
	}
	
	/** Gets the cost of using this router link.
	 * @return the cost */
	public int getMetric() {
		return metric;
	}
		
	/** Gets link prefix.
	 * @return the prefix */
	public Ip4AddressPrefix getLinkAddressPrefix() {
		return link_addr_prefix;
	}
		
	/** Gets field length.
	 * @return the length */
	public int getLength() {
		return 12+4*(tos!=null?tos.length:0);
	}
	
	/** Gets bytes of this link field.
	 * @param buf buffer containing the link field
	 * @param off offset of the link field within the buffer
	 * @return field length */
	public int getBytes(byte[] buf, int off) {
		link_addr_prefix.getBytes(buf,off);
		System.arraycopy(link_addr_prefix.getPrefix().prefixMask(),0,buf,off+4,4);
		buf[off+8]=(byte)type;
		int tos_len=tos!=null?tos.length:0;
		buf[off+9]=(byte)tos_len;
		ByteUtils.intToTwoBytes(metric,buf,off+10);
		for (int i=0; i<tos_len; i++) {
			buf[off+12+i*4]=(byte)tos[i];
			ByteUtils.intToTwoBytes(tos_metric[i],buf,off+14+i*4);
		}
		return 12+4*tos_len;
	}
	
	@Override
	public String toString() {
		return link_addr_prefix.toStringWithPrefixLength()+":"+metric;
	}


}
