package it.unipr.netsec.nemo.examples.p1;


import java.util.Arrays;

import it.unipr.netsec.ipstack.net.Address;


/** Address containing a pair of indexes i,j.
 */
public class P1Address implements Address {

	/** Index i */
	int i;
	
	/** Index i */
	int j;

	
	/** Creates a new address.
	 * @param i index i
	 * @param j index j */
	public P1Address(int i, int j) {
		this.i=i; this.j=j;
	}
	
	/** Creates a new address.
	 * @param ij the i,j string */
	public P1Address(String ij) {
		String[] a=ij.split(",");
		i=Integer.parseInt(a[0]);
		i=Integer.parseInt(a[1]);
	}

	public int getI() {
		return i;
	}

	public int getJ() {
		return j;
	}

	/** Gets the address length. */
	/*public int length() {
		return toString().length();
	}*/

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof P1Address)) return false;
		P1Address a=(P1Address)o;
		return i==a.i && j==a.j;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(getBytes());
	}
	
	@Override
	public String toString() {
		return ""+i+","+j;
	}
	
	@Override
	public byte[] getBytes() {
		return toString().getBytes();
	}

	@Override
	public int getBytes(byte[] buf, int off) {
		byte[] data=getBytes();
		System.arraycopy(data,0,buf,off,data.length);
		return data.length;
	}

}
