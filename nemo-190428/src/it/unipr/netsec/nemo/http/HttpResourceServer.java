package it.unipr.netsec.nemo.http;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;

import it.unipr.netsec.ipstack.tcp.ServerSocket;
import it.unipr.netsec.ipstack.tcp.Socket;
import it.unipr.netsec.ipstack.tcp.TcpLayer;

import java.util.Date;

import org.zoolu.util.Clock;
import org.zoolu.util.DateFormat;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;


/** Very simple HTTP resource server.
 * <p>
 * It handles only GET requests for a single resource with path "/".
 */
public class HttpResourceServer {
	
	/** Verbose mode */
	public static boolean VERBOSE=false;

	/** Logs a message. */
	private void log(String str) {
		SystemUtils.log(LoggerLevel.INFO,getClass(),str);
	}

	
	/** Server socket */
	ServerSocket server_socket;
	
	
	/** Creates a new HTTP server. 
	 * @throws IOException */
	public HttpResourceServer(TcpLayer tcp, int server_port, String content_type, String resource_value) throws IOException {
		server_socket=new ServerSocket(tcp,server_port);
		serve(content_type,resource_value);
	}
	
	
	/** Starts the server.
	 * @param content_type the resource content type
	 * @param resource_value the resource value
	 * @throws IOException */
	private void serve(final String content_type, final String resource_value) throws IOException {
		if (VERBOSE) log("serve(): listening on port "+server_socket.getLocalPort()); 
		while (true) {
			final Socket socket=server_socket.accept();
			if (VERBOSE) log("serve(): new TCP connection"); 
			new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						serve(socket,content_type,resource_value);
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
	 * @param content_type the resource content type
	 * @param resource_value the resource value
	 * @throws IOException */
	private void serve(Socket socket, String content_type, String resource_value) throws IOException {
		BufferedReader is=new BufferedReader(new InputStreamReader(socket.getInputStream()));
		String line=is.readLine();
		if (VERBOSE) log("Request: "+line);
		// status code
		int status_code=500;
		if (!line.startsWith("GET ")) status_code=405;
		else
		if (line.substring(4).trim().startsWith("/ ")) status_code=200;
		else status_code=404;
		// response
		StringBuffer response=new StringBuffer();
		response.append("HTTP/1.1 ").append(status_code).append(' ').append(HttpStatusCode.reasonOf(status_code)).append("\r\n");
		response.append("Date: "+DateFormat.formatEEEddMMMyyyyhhmmss(new Date(Clock.getDefaultClock().currentTimeMillis()))+"\r\n");
		response.append("Server: ipstack\r\n");
		if (status_code==200) {
			response.append("Content-Type: "+content_type+"\r\n");
			response.append("Content-Length: "+resource_value.length()+"\r\n");
			response.append("Connection: Closed\r\n");
			response.append("\r\n");
			response.append(resource_value);
		}
		else {
			response.append("Content-Length: 0\r\n");
			response.append("Connection: Closed\r\n");
			response.append("\r\n");
		}
		if (VERBOSE) log("Response: "+response+"-----End-of-message-----");
		OutputStream os=socket.getOutputStream();
		os.write(response.toString().getBytes());
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
