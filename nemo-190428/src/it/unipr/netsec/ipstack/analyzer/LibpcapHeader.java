package it.unipr.netsec.ipstack.analyzer;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


import org.zoolu.util.ByteUtils;

/** Libpcap Global Header.
 * The header starts libpcap files and is followed by the sequence of libpcap packet records.
 * <p>
 * The header specifies the file format version (current version is 2.4), the time zone, the accuracy of timestamps,
 * the length of captured packets, and the type of link.
 * <!--<p>
 * @see <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat">wiki.wireshark.org/Development/LibpcapFileFormat</a> for details.
 * -->
 */
public class LibpcapHeader {

	/** Standard magic number */
	static final long MAGIC_NUMBER=0xa1b2c3d4L;

	/** Standard magic number swapped */
	static final long MAGIC_NUMBER_SWAPPED=0xd4c3b2a1;

	
	/** BSD loopback encapsulation.
	 * The link layer header is a 4-byte field, in host byte order, containing a value of 2 for IPv4 packets,
	 * a value of either 24, 28, or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23 for IPX packets.
	 * All of the IPv6 values correspond to IPv6 packets; code reading files should check for all of them. */
	public static final int LINKTYPE_NULL=0;
	
	/** IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up). */
	public static final int LINKTYPE_ETHERNET=1;

	/** SLIP, encapsulated with a LINKTYPE_SLIP header. */
	public static final int LINKTYPE_SLIP=8;

	/** DLT_PPP	PPP, as per RFC 1661 and RFC 1662.
	 * If the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP header following those two bytes,
	 * otherwise it's PPP without framing, and the packet begins with the PPP header. */
	public static final int LINKTYPE_PPP=9;

	/** PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547.
	 * The first byte will be 0xFF for PPP in HDLC-like framing, and will be 0x0F or 0x8F for Cisco PPP with HDLC framing. */
	public static final int LINKTYPE_PPP_HDLC=50;

	/** PPPoE; the packet begins with a PPPoE header, as per RFC 2516. */
	public static final int LINKTYPE_PPP_ETHER=51;

	/** Raw IP.
	 * The packet begins with an IPv4 or IPv6 header, with the "version" field of the header indicating whether it's an IPv4 or IPv6 header. */
	public static final int LINKTYPE_RAW=101;

	/** IEEE 802.11 wireless LAN. */
	public static final int LINKTYPE_IEEE802_11=105;

	/** OpenBSD loopback encapsulation.
	 *  The link-layer header is a 4-byte field, in network byte order, containing a value of 2 for IPv4 packets,
	 *  a value of either 24, 28, or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23 for IPX packets.
	 *  All of the IPv6 values correspond to IPv6 packets; code reading files should check for all of them. */
	public static final int LINKTYPE_LOOP=108;

	/** Bluetooth HCI UART transport layer.
	 * The frame contains an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification,
	 * followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification. */
	public static final int LINKTYPE_BLUETOOTH_HCI_H4=187;

	/** USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree.
	 * Only the first 48 bytes of that header are present. All fields in the header are in host byte order.
	 * When performing a live capture, the host byte order is the byte order of the machine on which the packets are captured.
	 * When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number;
	 * when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block. */
	public static final int LINKTYPE_USB_LINUX=189;

	/** Link Access Procedure, Balanced (LAPB), as specified by ITU-T Recommendation X.25,
	 * preceded with a one-byte pseudo-header with a zero value meaning "received by this host" (DCE-DTE) and a non-zero value meaning "sent by this host" (DTE-DCE). */
	public static final int LINKTYPE_LAPB_WITH_DIR=207;

	/** Raw IPv4.
	 * The packet begins with an IPv4 header. */
	public static final int LINKTYPE_IPV4=228;

	/** Raw IPv6.
	 * The packet begins with an IPv6 header. */
	public static final int LINKTYPE_IPV6=229;

	

	/** Magic number [32bit] */
	long magic_number=MAGIC_NUMBER;
	
	/** Major version number [16bit] */
	int version_major=2;
	
	/** Minor version number [16bit] */
	int version_minor=4;

	/** GMT to local correction [32bit] */
	int thiszone=0;
	
	/** Accuracy of timestamps [32bit] */
	int sigfigs=0;
	
	/** Max length of captured packets, in octets [32bit] */
	int snaplen=262144;

	/** Data link type [32bit] */
	int network=LINKTYPE_ETHERNET;

	
	private static byte[] INT16_BUFFER=new byte[2];
	private static byte[] INT32_BUFFER=new byte[4];
	
	private synchronized int readInt16(InputStream is) throws IOException {
		int len=is.read(INT16_BUFFER);
		if (len!=2) throw new IOException("Too few bytes availables ("+len+")");
		return ByteUtils.twoBytesToIntLittleEndian(INT16_BUFFER);
	}

	private synchronized long readInt32(InputStream is) throws IOException {
		int len=is.read(INT32_BUFFER);
		if (len!=4) throw new IOException("Too few bytes availables ("+len+")");
		return ByteUtils.fourBytesToIntLittleEndian(INT32_BUFFER);
	}

	private synchronized void writeInt16(OutputStream os, int n) throws IOException {
		ByteUtils.intToTwoBytesLittleEndian(n,INT16_BUFFER,0);
		os.write(INT16_BUFFER);
	}

	private synchronized void writeInt32(OutputStream os, long n) throws IOException {
		ByteUtils.intToFourBytesLittleEndian(n,INT32_BUFFER,0);
		os.write(INT32_BUFFER);
	}


	/** Creates a new header. */
	public LibpcapHeader() {
	}

	/** Creates a new header.
	 * @param link_type the type of link (e.g. {@link #LINKTYPE_ETHERNET}, {@link #LINKTYPE_RAW}, {@link #LINKTYPE_IPV4}, {@link #LINKTYPE_IPV6}, etc.). */
	public LibpcapHeader(int link_type) {
		this.network=link_type;
	}
	
	/** Creates a new header.
	 * @param link_type the type of link (e.g. {@link #LINKTYPE_ETHERNET}, {@link #LINKTYPE_RAW}, {@link #LINKTYPE_IPV4}, {@link #LINKTYPE_IPV6}, etc.).
	 * @param time_zone GMT to local correction */
	public LibpcapHeader(int link_type, int time_zone) {
		this.thiszone=time_zone;
	}
	
	/** Gets major version.
	 * @return the major version */
	public int getVersionMajor() {
		return version_major;
	}
	
	/** Gets minor version.
	 * @return the minor version */
	public int getVersionMinor() {
		return version_minor;
	}
	
	/** Gets time zone.
	 * @return GMT to local correction */
	public int getTimezone() {
		return thiszone;
	}
	
	/** Gets time accuracy.
	 * @return the accuracy of timestamps */
	public int getSigfigs() {
		return sigfigs;
	}
	
	/** Gets snap length.
	 * @return the maximum length of captured packets, in octets */
	public int getSnaplen() {
		return snaplen;
	}
	
	/** Gets the link type.
	 * @return the type of link (e.g. 1={@link #LINKTYPE_ETHERNET}, 101={@link #LINKTYPE_RAW}, 228={@link #LINKTYPE_IPV4}, 229={@link #LINKTYPE_IPV6}, etc.). */
	public int getLinkType() {
		return network;
	}
	
	/** Reads a new header from a given input stream.
	 * @param is the input stream
	 * @return the number of bytes that have been read
	 * @throws IOException */
	public synchronized int read(InputStream is) throws IOException {	
		magic_number=readInt32(is);
		if (magic_number!=MAGIC_NUMBER) throw new IOException("Reverse order not supported");
		version_major=readInt16(is);
		version_minor=readInt16(is);
		thiszone=(int)readInt32(is);
		sigfigs=(int)readInt32(is);
		snaplen=(int)readInt32(is);
		network=(int)readInt32(is);
		return 24;
	}
	
	/** Writes the header to an output stream.
	 * @param os the output stream
	 * @return the the number of bytes that have been written */
	public int write(OutputStream os) throws IOException {	
		writeInt32(os,magic_number);
		writeInt16(os,version_major);
		writeInt16(os,version_minor);
		writeInt32(os,thiszone);
		writeInt32(os,sigfigs);
		writeInt32(os,snaplen);
		writeInt32(os,network);
		return 24;
	}

	@Override
	public String toString() {	
		StringBuffer sb=new StringBuffer();
		sb.append("magic-number: "+Long.toHexString(magic_number)+"\n");
		sb.append("version: "+version_major+"."+version_minor+"\n");
		sb.append("thiszone: "+thiszone+"\n");
		sb.append("sigfigs: "+sigfigs+"\n");
		sb.append("snaplen: "+snaplen+"\n");
		sb.append("network: "+network+"\n");
		return sb.toString();
	}
}
