package it.unipr.netsec.nemo.http;


import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;


public class HttpRequest extends HttpMessage {

	/*public HttpRequest() {
	}*/

	public HttpRequest(String method, String request_url, HashMap<String, String> header_fields, byte[] body) {
		super(method+" "+request_url+" HTTP/1.1",header_fields,body);
	}

	public HttpRequest(HttpMessage msg) {
		super(msg);
	}
	
	public static HttpRequest parseHttpRequest(InputStream is) throws IOException {
		return new HttpRequest(HttpMessage.parseHttpMessage(is));
	}
	
	public String getMethod() {
		String[] request_line_fields=first_line.split("\\s+");
		return request_line_fields[0];
	}

	public String getRequestURL() {
		String[] request_line_fields=first_line.split("\\s+");
		return request_line_fields[1];
	}

	public String getVersion() {
		String[] request_line_fields=first_line.split("\\s+");
		return request_line_fields[2];
	}

}
