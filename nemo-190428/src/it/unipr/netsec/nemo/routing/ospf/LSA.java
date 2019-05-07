package it.unipr.netsec.nemo.routing.ospf;

import org.zoolu.util.ByteUtils;

import it.unipr.netsec.ipstack.ip4.Ip4Address;

/** Link-state advertisement.
 */
public class LSA {

	/** Router-LSA type */
	public static final int TYPE_Router=1;

	/** Network-LSA type */
	public static final int TYPE_Network=2;

	/** Summary-LSA type when the destination is an IP network */
	public static final int TYPE_Summary_Network=3;

	/** Summary-LSA type when the destination is an AS boundary router */
	public static final int TYPE_Summary_AS=4;

	/** AS-external-LSA type */
	public static final int TYPE_AS_External=2;

	
	/** Age - the time in seconds since the LSA was originated */
	int age;

	/** Options - the optional capabilities supported by the described portion of the routing domain */
	int options;
	
	/** Type - the type of the LSA */
	int type;

	/** Link-State ID */
	long id;
	
	/** Advertising Router */
	Ip4Address router;

	/** LS sequence number */
	long sqn;
	
	/** LS body */
	byte[] body;

	
	/** Creates a new LSA.
	 * @param lsa the LSA */
	protected LSA(LSA lsa) {
		this(lsa.type,lsa.age,lsa.id,lsa.router,lsa.sqn,lsa.body);
	}
	
	/** Creates a new LSA.
	 * @param type the type of the LSA
	 * @param age the time in seconds since the LSA was originated
	 * @param id Link-State ID
	 * @param router advertising router
	 * @param sqn LS sequence number
	 * @param body the LSA body, that is the LSA excluding the LSA header (first 20 bytes) */
	public LSA(int type, int age, long id, Ip4Address router, long sqn, byte[] body) {
		this(type,age,id,router,sqn,body,0,body.length);
	}

	/** Creates a new LSA.
	 * @param type the type of the LSA
	 * @param age the time in seconds since the LSA was originated
	 * @param id Link-State ID
	 * @param router advertising router
	 * @param sqn LS sequence number
	 * @param buf buffer containing the LSA body, that is the LSA excluding the LSA header (first 20 bytes)
	 * @param off the offset within the buffer
	 * @param len the length of the LSA body, that is the LSA length minus 20 */
	public LSA(int type, int age, long id, Ip4Address router, long sqn, byte[] buf, int off, int len) {
		this.type=type;
		this.age=age;
		this.id=id;
		this.router=router;
		this.sqn=sqn;
		this.body=new byte[len];
		System.arraycopy(buf,off,body,0,len);		
	}

	/** Creates a new LSA.
	 * @param buf buffer containing the LSA
	 * @param off the offset within the buffer */
	public LSA(byte[] buf, int off) {
		age=ByteUtils.twoBytesToInt(buf,off);
		options=0xff&buf[off+2];
		type=0xff&buf[off+3];
		id=ByteUtils.fourBytesToInt(buf,off+4);
		router=new Ip4Address(buf,off+8);
		sqn=ByteUtils.fourBytesToInt(buf,off+12);
		int len=ByteUtils.twoBytesToInt(buf,off+18);
		body=new byte[len];
		System.arraycopy(buf,off+20,body,0,len-20);	
	}

	/** Gets LS age.
	 * @return the age value */
	public int getAge() {
		return age;
	}

	/** Gets the optional capabilities supported by the described portion of the routing domain.
	 * @return the options */
	public int getOptions() {
		return options;
	}

	/** Gets LS type.
	 * @return the type */
	public int getType() {
		return type;
	}

	/** Gets the Link State ID.
	 * @return the identifier */
	public int getID() {
		return type;
	}

	/** Gets the Advertising Router.
	 * @return ID of the router that originated the LSA */
	public Ip4Address getRouter() {
		return router;
	}

	/** Gets LS sequence number.
	 * @return the sequence number */
	public long getSequenceNumber() {
		return sqn;
	}

	/** Gets LSA length.
	 * @return the length */
	public int getLength() {
		return 20+body.length;
	}

	/** Gets LSA bytes.
	 * @param buf buffer containing the LSA
	 * @param off offset within the buffer
	 * @return LSA length */
	public int getBytes(byte[] buf, int off) {
		ByteUtils.intToTwoBytes(age,buf,off);
		buf[off+2]=(byte)options;
		buf[off+3]=(byte)type;
		ByteUtils.intToFourBytes(id,buf,off+4);
		router.getBytes(buf,off+8);
		ByteUtils.intToFourBytes(sqn,buf,off+12);
		ByteUtils.intToTwoBytes(20+body.length,buf,off+18);
		System.arraycopy(body,0,buf,off+20,body.length);
		return 20+body.length;
	}


}
