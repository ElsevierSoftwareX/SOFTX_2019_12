package it.unipr.netsec.nemo.http;


import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;


public class HttpResponse extends HttpMessage {

	/*public HttpResponse() {
	}*/

	public HttpResponse(int status_code, HashMap<String, String> header_fields, byte[] body) {
		super("HTTP/1.1 "+String.valueOf(status_code)+" "+HttpStatusCode.reasonOf(status_code),header_fields,body);
	}

	public HttpResponse(HttpMessage msg) {
		super(msg);
	}
	
	public HttpResponse parseMessage(InputStream is) throws IOException {
		return new HttpResponse(HttpMessage.parseHttpMessage(is));
	}
	
	public int getStatusCode() {
		String[] status_line_fields=first_line.split("\\s+");
		return Integer.parseInt(status_line_fields[1]);
	}

	public String getReason() {
		String status_code=first_line.split("\\s+")[1];
		return first_line.substring(first_line.indexOf(status_code)+4).trim();
	}

}
