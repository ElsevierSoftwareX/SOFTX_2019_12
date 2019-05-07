package test;


import java.io.IOException;
import java.io.OutputStream;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import it.unipr.netsec.nemo.http.HttpRequest;
import it.unipr.netsec.nemo.http.HttpRequestHandle;
import it.unipr.netsec.nemo.http.HttpResponse;
import it.unipr.netsec.nemo.http.HttpServerListener;

import java.util.Date;
import java.util.HashMap;

import org.zoolu.util.DateFormat;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;


/** Very simple HTTP server.
 */
public class MicroHttpd {
	
	/** Verbose mode */
	public static boolean VERBOSE=true; // false

	/** Logs a message. */
	private static void log(String str) {
		SystemUtils.log(LoggerLevel.INFO,MicroHttpd.class,str);
	}

	
	/** Default server port */
	public static int DEFAULT_PORT=80; // 8080

	/** Default resource */
	public static String DEFAULT_RESOURCE="index.html";

	/** Server socket */
	ServerSocket server_socket;
	
	/** Server listener */
	HttpServerListener listener;
	
	
	/** Creates a new HTTP server.
	 * @param server_port server port
	 * @param listener server listener that handles HTTP requests
	 * @throws IOException */
	public MicroHttpd(int server_port, HttpServerListener listener) throws IOException {
		server_socket=new ServerSocket(server_port);
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
		header_fields.put("Date",DateFormat.formatEEEddMMMyyyyhhmmss(new Date(System.currentTimeMillis())));
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
	
	
	/** The main method. */
	public static void main(String[] args) throws IOException {
		Flags flags=new Flags(args);
		VERBOSE|=flags.getBoolean("-v","verbose mode");
		boolean help=flags.getBoolean("-h","prints this message");
		int server_port=flags.getInteger("-p","<port>",DEFAULT_PORT,"server port (default is "+DEFAULT_PORT+")");
		
		if (help) {
			System.out.println(flags.toUsageString(TuntapHost.class.getSimpleName()));
			System.exit(0);					
		}
		if (VERBOSE) {
			SystemUtils.setDefaultLogger(new LoggerWriter(System.out));
		}
		
		new MicroHttpd(server_port,new HttpServerListener() {
			@Override
			public void onHttpRequest(HttpRequestHandle req_handle) {
				if (req_handle.getMethod().equals("GET")) {
					String resource_url=req_handle.getRequestURL();
					if (resource_url.equals("/")) resource_url=DEFAULT_RESOURCE;
					else {
						// clean the resource URL
						while (resource_url.length()>0 && resource_url.charAt(0)=='/') resource_url=resource_url.substring(1);
						if (resource_url.indexOf("..")>=0) {
							req_handle.setResponseCode(403);
							return;
						}
					}
					log("Resource: "+resource_url);
					try {
						Path fileLocation = Paths.get(resource_url);
						byte[] data=Files.readAllBytes(fileLocation);
						req_handle.setResourceValue(data);
						String content_type="application/octet-stream";
						if (resource_url.endsWith(".html") || resource_url.endsWith(".htm")) content_type="text/html";
						else if (resource_url.endsWith(".txt")) content_type="text/plain";
						else if (resource_url.endsWith(".java")) content_type="text/plain";
						req_handle.setContentType(content_type);
						req_handle.setResponseCode(200);
					}
					catch (IOException e) {
						//e.printStackTrace();
						req_handle.setResponseCode(404);
					}
				}
			}			
		});
	}


}
