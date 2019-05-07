package it.unipr.netsec.ipstack.dhcp;


import java.util.Vector;
import java.util.Hashtable;
import java.util.Date;


/** Class AddressDatabase allows the management of allocated IP addresses */
public class AddressDatabase {
	
	Vector times; // expiration time (date)
	Vector cids; // client IDs, i.e. its ph address or client_id (if present) 
	Hashtable addresses; // ip addresses inserted by phid (phid is the hashtable key)
	Hashtable tseqnums; // timeout sequence numbers inserted by ip address (ip address is the hashtable key)
	
	/** Costructs the database */
	public AddressDatabase() {
		times=new Vector ();
		cids=new Vector ();
		addresses=new Hashtable();
		tseqnums=new Hashtable();
	}
	
	/** Adds a new IP address, associated with its unique ID (e.g. the PH address) and expiration time. 
	  * It returns false if the IP address or the PH address is already present. */ 
	public boolean put(String address, String cid, long exptime) {
		if (!addresses.containsKey(cid) && !tseqnums.containsKey(address)) {
			Date now=new Date();
			Date time=new Date(now.getTime()+1000*exptime);
			int tseq=times.size();
			for (int i=0; i<times.size(); i++)
				if (((Date)times.elementAt(i)).after(time)) { tseq=i; break; }
			times.add(tseq,time);
			cids.add(tseq,cid);
			addresses.put(cid,address);
			tseqnums.put(address,new Integer(tseq));
			return true;
		}
		else return false;
	}
	
	/** Removes an IP address form the database */
	public void remove(String address) {
		if (tseqnums.containsKey(address)) {
			int tseq=((Integer)tseqnums.remove(address)).intValue();
			String cid=(String)cids.elementAt(tseq);
			cids.removeElementAt(tseq);
			times.removeElementAt(tseq);
			addresses.remove(cid);
			for (int i=tseq; i<times.size(); i++)
				tseqnums.put(addresses.get(cids.get(i)), new Integer(i));
		}
	}
	
	/** Returns true if the database contains the IP address */
	public boolean containsAddress(String address) {
		return tseqnums.containsKey(address);
	}
	
	/** Returns true if the database contains the client ID (e.g. the PH address) */
	public boolean containsCid(String cid) {
		return addresses.containsKey(cid);
	}

	/** Returns the IP address associated to a client ID (e.g. the PH address) */
	public String getAddress(String cid) {
		return (String)addresses.get(cid);
	}

	/** Renews a lease */
	public void renew(String addr, long exptime) {
		if (tseqnums.containsKey(addr)) {
			int tseq=((Integer)tseqnums.get(addr)).intValue();
			String cid=(String)cids.elementAt(tseq);
			times.removeElementAt(tseq);
			cids.removeElementAt(tseq);
			tseqnums.remove(addr);
			for (int i=tseq; i<times.size(); i++)
				tseqnums.put(addresses.get(cids.get(i)), new Integer(i));
						
			Date now=new Date();
			Date time=new Date(now.getTime()+1000*exptime);
			tseq=times.size();
			for (int i=0; i<times.size(); i++)
				if (((Date)times.elementAt(i)).after(time)) { tseq=i; break; }
			times.add(tseq,time);
			cids.add(tseq,cid);
			tseqnums.put(addr,new Integer(tseq));
		}
	}
	
	/** Returns the first expired IP address still in the database */
	public String getExpiredAddress() {
		if (times.size()>0 && ((Date)times.elementAt(0)).before(new Date()))
			return (String)addresses.get(cids.elementAt(0));
		else
			return null;
	}
	
	/** Gets the number of allcated addreses */
	public int size() {
		return addresses.size();
	}
}
