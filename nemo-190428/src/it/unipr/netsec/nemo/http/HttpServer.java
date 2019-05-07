package it.unipr.netsec.nemo.http;


import java.io.IOException;
import java.io.OutputStream;

import it.unipr.netsec.ipstack.tcp.ServerSocket;
import it.unipr.netsec.ipstack.tcp.Socket;
import it.unipr.netsec.ipstack.tcp.TcpLayer;

import java.util.Date;
import java.util.HashMap;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** Very simple HTTP server.
 */
public class HttpServer {
	
	/** Verbose mode */
	public static boolean VERBOSE=false;

	/** Logs a message. */
	private void log(String str) {
		SystemUtils.log(LoggerLevel.INFO,getClass(),str);
	}

	
	/** Server socket */
	ServerSocket server_socket;
	
	/** Server listener */
	HttpServerListener listener;
	
	
	/** Creates a new HTTP server.
	 * @param tcp TCP layer
	 * @param server_port server port
	 * @param listener server listener that handles HTTP requests
	 * @throws IOException */
	public HttpServer(TcpLayer tcp, int server_port, HttpServerListener listener) throws IOException {
		server_socket=new ServerSocket(tcp,server_port);
		this.listener=listener;
		serve();
	}
	
	
	/** Starts the server.
	 * @throws IOException */
	private void serve() throws IOException {
		if (VERBOSE) log("serve(): listening on port "+server_socket.getLocalPort()); 
		while (true) {
			final Socket socket=server_socket.accept();
			if (VERBOSE) log("serve(): new TCP connection"); 
			new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						serve(socket);
					}
					catch (IOException e) {
						e.printStackTrace();
					}		
				}				
			}).start();
		}
	}

	
	/** Handles a connection.
	 * @param socket the new TCP connection
	 * @throws IOException */
	private void serve(Socket socket) throws IOException {
		// request
		HttpRequest req=HttpRequest.parseHttpRequest(socket.getInputStream());
		if (VERBOSE) log("Request: "+req+"-----End-of-message-----");
		HttpRequestHandle request_handle=new HttpRequestHandle(req.getMethod(),req.getRequestURL());
		listener.onHttpRequest(request_handle);	
		// response
		HashMap<String,String> header_fields=new HashMap<String,String>();
		header_fields.put("Date",DateFormat.formatEEEddMMMyyyyhhmmss(new Date(Clock.getDefaultClock().currentTimeMillis())));
		header_fields.put("Server","Nemo Httpd");
		byte[] resource_value=request_handle.getResourceValue();
		String content_type=request_handle.getContentType();
		if (resource_value!=null && content_type!=null) header_fields.put("Content-Type",content_type);
		HttpResponse resp=new HttpResponse(request_handle.getResponseCode(),header_fields,resource_value);
		if (VERBOSE) log("Response: "+resp+"-----End-of-message-----");
		OutputStream os=socket.getOutputStream();
		os.write(resp.getBytes());
		os.flush();
		socket.close();		
	}

	
	/** Stops the server. */
	public void close() {
		try {
			server_socket.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

}
