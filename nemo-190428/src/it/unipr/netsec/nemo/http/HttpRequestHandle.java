package it.unipr.netsec.nemo.http;


/** Contains a HTTP request and the associated response information.
 */
public class HttpRequestHandle {

	/** Request method */
	String method;

	/** Request URL */
	String request_url;

	/** Status code */
	int status_code=500;

	/** Content type */
	String content_type=null;

	/** Resource value */
	byte[] resource_value=null;

	
	/** Creates a new exchange.
	 * @param method HTTP request method
	 * @param request_url request URL */
	public HttpRequestHandle(String method, String request_url) {
		this.method=method;
		this.request_url=request_url;
	}
	

	/** Gets the request method.
	 * @return the method */
	public String getMethod() {
		return method;
	}

	/** Gets the request URL.
	 * @return the URL */
	public String getRequestURL() {
		return request_url;
	}

	/** Sets the status code.
	 * @param status_code the status code of the response */
	public void setResponseCode(int status_code) {
		this.status_code=status_code;
	}

	/** Gets the status code of the response.
	 * @return the status code */
	public int getResponseCode() {
		return status_code;
	}

	/** Sets the content type of the response.
	 * @param content_type the content type to set */
	public void setContentType(String content_type) {
		this.content_type=content_type;
	}

	/** Gets the content type of the response.
	 * @return the content type */
	public String getContentType() {
		return content_type;
	}

	/** Sets the resource value of the response.
	 * @param resource_value the resource value to set
	 */
	public void setResourceValue(byte[] resource_value) {
		this.resource_value=resource_value;
	}
	
	/** Gets the resource value of the response.
	 * @return the resource_value */
	public byte[] getResourceValue() {
		return resource_value;
	}

}
