package it.unipr.netsec.nemo.http;


/** Handles HTTP requests.
 */
public interface HttpServerListener {
	
	public void onHttpRequest(HttpRequestHandle req);
	
}
