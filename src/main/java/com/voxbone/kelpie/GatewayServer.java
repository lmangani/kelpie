/**
 *    Copyright 2012 Voxbone SA/NV
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.voxbone.kelpie;


import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.spi.SelectorProvider;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;

import org.jabberstudio.jso.util.Utilities;

/**
 * Main class
 * starts the listeners for xmpp and sip traffic
 * @author torrey
 *
 */
public class GatewayServer 
{

	private String host;
	private int port;
	
	Logger logger = Logger.getLogger(this.getClass());


	public GatewayServer(String host, int port) 
	{
		if (!Utilities.isValidString(host))
		{
			throw new IllegalArgumentException("Host cannot be null or \"\"");
		}
		this.host = host;

		if (port < 1)
		{
			throw new IllegalArgumentException("Port cannot be less than 1");
		}
		this.port = port;
	}

	public String getHostName() 
	{
		return host;
	}

	public int getPort() 
	{
		return port;
	}
	
	public void execute() throws Exception 
	{
		ServerSocketChannel ssc = ServerSocketChannel.open();
		SocketChannel sc;
		SelectionKey key;
		Iterator<SelectionKey> itr;
		
		Selector sel = SelectorProvider.provider().openSelector();
		
		// Setup server socket
		ssc.configureBlocking(false);
		ssc.socket().bind(new InetSocketAddress(getPort()));
		ssc.register(sel, SelectionKey.OP_ACCEPT);

		int nextInternalCallId = 0;
		
		logger.info("Ready for connections");

		while (true) 
		{
			if (sel.select() > 0) 
			{
				// Process selected keys
				itr = sel.selectedKeys().iterator();
				while (itr.hasNext()) 
				{
					key = (SelectionKey) itr.next();
					itr.remove();

					if (key.isAcceptable()) 
					{
						sc = ((ServerSocketChannel) key.channel()).accept();
						sc.configureBlocking(false);
						sc.socket().setSoLinger(true, 0);
						if (sc.isConnectionPending())
						{
							sc.finishConnect();
						}

						String internalCallId = "GWS" + String.format("%08x", nextInternalCallId++);
						logger.info("Adding session [[" + internalCallId + "]]");
						@SuppressWarnings("unused")
						Session sess = new Session(internalCallId, getHostName(), sc);
					} 
				}
			}
		}
	}

	private static class InitThread extends Thread
	{
		public void run()
		{
			try
			{
				Thread.sleep(5000);
			} 
			catch (InterruptedException e)
			{
				// ignore
 			}
			UriMappings.initialize();
		}
	}
	
	public static final void main(String [] args) throws Exception 
	{
		GatewayServer server;
		String host = null;
		String port = null;
	   
		Properties properties = ConfigurationUtil.getPropertiesResource("server");
		
		Presence.configure(properties);
		Session.configure(properties);
		SipSubscriptionManager.configure(properties);
		UriMappings.configure(properties);
		RtpRelay.configure(properties);
		

		host = properties.getProperty("com.voxbone.kelpie.hostname");
		port = "5269";
		
		@SuppressWarnings("unused")
		SipService sipService = new SipService(properties);
		SipSubscriptionManager.loadData();
		// Create and start server
		server = new GatewayServer(host, Integer.parseInt(port));
		new InitThread().start();
		server.execute();
	}

}
