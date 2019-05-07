package it.unipr.netsec.nemo.routing.ospf;


import java.util.Arrays;

import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;


/** Router-LSA.
 */
public class RouterLSA extends LSA {

	/** Bit V - Virtual link endpoint */
	//boolean bit_v=false;

	/** Bit E - External */
	//boolean bit_e=false;

	/** Bit B - Border */
	//boolean bit_b=false;
	
	/** Links */
	//LSALink[] links;

	
	/** Creates a new Router-LSA.
	 * @param lsa the Router-LSA */
	public RouterLSA(LSA lsa) {
		super(lsa);
		if (type!=LSA.TYPE_Router) throw new RuntimeException("LSA packet type missmatches ("+type+"): it is not Router-LSA ("+LSA.TYPE_Router+")");		
	}
	
	/** Creates a new Router-LSA.
	 * @param age the time in seconds since the LSA was originated
	 * @param id Link-State ID
	 * @param router advertising router
	 * @param sqn LS sequence number
	 * @param links array of link fields */
	public RouterLSA(int age, long id, Ip4Address router, long sqn, LSALink[] links) {
		super(LSA.TYPE_Router,age,id,router,sqn,linksToBytes(links));
	}
	
	/** Gets a byte array containing an array of LSALink.
	 * @param links array of LSALink
	 * @return the byte array */
	private static byte[] linksToBytes(LSALink[] links) {
		int len=4; // V,E,B bits and link number
		for (LSALink link : links) len+=link.getLength();
		byte[] data=new byte[len];
		ByteUtils.intToTwoBytes(links.length,data,2);
		int off=4;
		for (LSALink link : links) {
			link.getBytes(data,off);
			off+=link.getLength();
		}
		return data;
	}

	/** Gets V bit (Virtual link endpoint).
	 * @return true=1, false=0 */
	public boolean getBitV() {
		return (body[0]&0x40)!=0;
	}
		
	/** Gets E bit (External).
	 * @return true=1, false=0 */
	public boolean getBitE() {
		return (body[0]&0x20)!=0;
	}
		
	/** Gets B bit (Border).
	 * @return true=1, false=0 */
	public boolean getBitB() {
		return (body[0]&0x10)!=0;
	}
		
	/** Gets the links.
	 * @return an array of LSALink */
	public LSALink[] getLinks() {
		int num=ByteUtils.twoBytesToInt(body,2);
		LSALink[] links=new LSALink[num];
		int off=4;
		for (int i=0; i<num; i++) {
			links[i]=new LSALink(body,off);
			off+=links[i].getLength();
		}
		return links;
	}

	@Override
	public String toString() {
		return router.toString()+", "+Arrays.toString(getLinks());
	}

}
