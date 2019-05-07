package it.unipr.netsec.nemo.http;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;


/** HTTP message as defined by RFC 7230.
  */
public class HttpMessage {

	/** HTTP version */
	protected static final String VERSION="HTTP/1.1"; 


	/** First line */
	protected String first_line=null;

	/** Header fields as table of pairs {name,value} */
	protected HashMap<String,String> header_fields=new HashMap<String,String>();

	/** Message body */
	protected byte[] body=null;


	/** Creates a new message.
	  * @param first_line the first line
	  * @param header_fields header fields
	  * @param body the message body */
	public HttpMessage(String first_line, HashMap<String,String> header_fields, byte[] body) {
		this.first_line=first_line;
		this.header_fields=header_fields;
		this.body=body;
		int len=body!=null? body.length : 0;
		header_fields.put("Content-Length",String.valueOf(len));
	}

	/** Creates a new message.
	  * @param msg the message to be copied */ 
	public HttpMessage(HttpMessage msg) {
		first_line=msg.first_line;
		for (String name: msg.header_fields.keySet()) header_fields.put(name,msg.header_fields.get(name));
		if (msg.body!=null) {
			body=new byte[msg.body.length];
			System.arraycopy(msg.body,0,body,0,body.length);
		}
	}

	/** Parses a message.
	 * @param is an input stream where the message has to be read from 
	 * @throws IOException */
	public static HttpMessage parseHttpMessage(InputStream is) throws IOException {
		BufferedReader in=new BufferedReader(new InputStreamReader(is));
		String first_line=in.readLine();
		HashMap<String,String> header_fields=new HashMap<String,String>();
		String line;
		while ((line=in.readLine()).length()>0) {
			int colon=line.indexOf(":");
			String name=line.substring(0,colon).trim();
			String value=line.substring(colon+1).trim();
			header_fields.put(name,value);
		}
		byte[] body=null;
		if (header_fields.containsKey("Content-Length")) {
			int len=Integer.parseInt(header_fields.get("Content-Length"));
			body=new byte[len];
			is.read(body,0,len);
		}
		return new HttpMessage(first_line,header_fields,body);
	}
	
	@Override
	public Object clone() {
		return new HttpMessage(this);
	}

	@Override
	public String toString() {
		StringBuffer sb=getHeader();
		if (body!=null) sb.append(new String(body));
		return sb.toString();
	}

  
	/** Gets the array of bytes of this message.
	  * @return an array of bytes containing this message */
	public byte[] getBytes() {
		byte[] header=getHeader().toString().getBytes();
		int len=header.length+(body!=null? body.length : 0);
		byte[] data=new byte[len];
		System.arraycopy(header,0,data,0,header.length);
		if (body!=null) System.arraycopy(body,0,data,header.length,body.length);
		return data;
	}


	/** Gets the message header.
	 * @return a string buffer formed by the first line, all header fields, an empty line */
	private StringBuffer getHeader() {
		StringBuffer sb=new StringBuffer();
		sb.append(first_line).append("\r\n");
		for (String name: header_fields.keySet()) sb.append(name).append(": ").append(header_fields.get(name)).append("\r\n");
		sb.append("\r\n");
		return sb;
	}


	/** Whether Message is a response. */
	public boolean isResponse() {
		if (first_line.startsWith("HTTP/")) return true;
		else return false;
	}
	
	/** Whether Message is a <i>method</i> request. */
	public boolean isRequest() {
		return !isResponse();
	}

	/** Sets the first line.
	 * @param first_line the first line */
	/*public void setFirstLine(String first_line) {
		this.first_line=first_line;
	}*/

	/** Gets the first line
	 * @return the first line */
	public String getFirstLine() {
		return first_line;
	}

	/** Whether it has a given header field.
	 * @param name name of the header field
	 * @return <i>true</i> if present, <i>true</i> if not */
	public boolean hasHeaderField(String name) {
		return header_fields.containsKey(name);
	}
	
	/** Adds a header field.
	  * The bottom is considered before the Content-Length and Content-Type headers. */
	/*public void addHeaderField(String name, String value)  {
		header_fields.put(name,value);
	}*/

	/** Gets the value of a given header field.
	 * @param name name of the header field
	 * @return the value */
	public String getHeaderField(String name) {
		return header_fields.get(name);
	}
  
	/** Whether Message has body. */   
	public boolean hasBody() {
		return body!=null;
	}

	/** Sets the message body.
	  * @param body the message body */
	/*public void setBody(byte[] body) {
		this.body=body;
		int len=body!=null? body.length : 0;
		header_fields.put("Content-Length",String.valueOf(len));
	}*/
	
	/** Gets the message body.
	 * @return the message body */
	public byte[] getBody() {
		return body;
	}  

}
