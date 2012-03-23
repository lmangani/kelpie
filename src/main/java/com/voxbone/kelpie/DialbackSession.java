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


import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.jabberstudio.jso.JID;
import org.jabberstudio.jso.JSOImplementation;
import org.jabberstudio.jso.NSI;
import org.jabberstudio.jso.Packet;
import org.jabberstudio.jso.Stream;
import org.jabberstudio.jso.StreamException;
import org.jabberstudio.jso.event.PacketEvent;
import org.jabberstudio.jso.event.PacketListener;
import org.jabberstudio.jso.io.src.ChannelStreamSource;
import org.jabberstudio.jso.util.Utilities;


/**
 * 
 * XMPP's Server to Server mechanism uses DNS based dialback auth, this connection deals
 * with the auth handshake
 * 
 */
public class DialbackSession extends Thread
{
	private JID local;
	private JID remote;
	private String sessionId;
	private String sessionKey;
	
	private String internalCallId;
	
	private Stream conn = null;
	private SocketChannel socketChannel = null;
	
	boolean valid = false;
	boolean done = false;
	
	Logger logger = Logger.getLogger(this.getClass());


	private class CallBackSession implements PacketListener
	{
		public void packetTransferred(PacketEvent evt)
		{
			logger.debug("[[" + internalCallId + "]] Got evt: " + evt.getData());
			
			if (evt.getData().getQualifiedName().equals("db:verify"))
			{
				logger.debug("[[" + internalCallId + "]] Got a Verify");
				if (evt.getData().getAttributeValue("type").equals("valid"))
				{
					logger.debug("[[" + internalCallId + "]] Session is valid :-)");
					valid = true;
				}
				else
				{
					logger.debug("[[" + internalCallId + "]] Session is not valid :-(");
					valid = false;
				}
				
				try
				{
					conn.disconnect();
				} 
				catch (StreamException e)
				{
					logger.error("Exception closing callback stream", e);
				}
			}
			evt.setHandled(true);
		}
	}

	public DialbackSession(String internalCallId, JID local, JID remote, String sessionId, String sessionKey)
	{
		this.local = local;
		this.remote = remote;
		this.sessionId = sessionId;
		this.sessionKey = sessionKey;
		
		this.internalCallId = internalCallId;
	}
	
	public boolean doDialback()
	{
		JSOImplementation jso = JSOImplementation.getInstance();
		conn = jso.createStream(Utilities.SERVER_NAMESPACE);
		conn.getOutboundContext().addNamespace("db", "jabber:server:dialback");

		conn.addStreamStatusListener(new StatusMonitor(internalCallId));

		conn.addPacketListener(PacketEvent.RECEIVED, new CallBackSession());

		try
		{
			logger.info("[[" + internalCallId + "]] Trying to connect to " + remote.getDomain());
			ArrayList<String> dests = DNSHelper.getSRVServerList(remote.getDomain(), "xmpp-server", "tcp");
			if (dests == null) 
			{
				logger.warn("[[" + internalCallId + "]] Record has no destinations.");
				return false;
			}
			logger.debug("[[" + internalCallId + "]] Record has " + dests.toString());
			String parts[];

			while (dests.size() > 0)
			{
				String dest = dests.remove(0);
				logger.debug("[[" + internalCallId + "]] Record resolves to " + dest);

				if (dest != null)
				{
					parts = dest.split(":");
				}
				else
				{
					// fallback to normal dns if no SRV record
					parts = new String[2];
					parts[0] = remote.getDomain();
					parts[1] = "5269";
				}

				try
				{
					InetSocketAddress addr = new InetSocketAddress(parts[0], Integer.parseInt(parts[1]));
					socketChannel = SocketChannel.open();
					socketChannel.socket().connect(addr, 5000);
					socketChannel.configureBlocking(false);
				}
				catch (IOException e)
				{
					logger.error("[[" + internalCallId + "]] Error connecting to server", e);
					continue;
				}
				break;
			}

			conn.connect(new ChannelStreamSource(socketChannel));
			conn.open();
			logger.info("[[" + internalCallId + "]] Streams established, sending verify");
			Packet p = conn.getDataFactory().createPacketNode(new NSI("verify", "jabber:server:dialback"), Packet.class);

			p.setID(sessionId);
			p.setFrom(local);
			p.setTo(remote);
			
			p.addText(sessionKey);
			conn.send(p);
			
			synchronized (this)
			{
				start();
				while (!done)
				{
					this.wait();
				}
			}
		} 
		catch (IllegalArgumentException e)
		{
			logger.error("Exception in doDialback", e);
		} 
		catch (IOException e)
		{
			logger.error("Exception in doDialback", e);
		} 
		catch (StreamException e)
		{
			logger.error("Exception in doDialback", e);
		} 
		catch (Exception e)
		{
			logger.error("Exception in doDialback", e);
		}
		
		return valid;
	}

	@Override
	public void run()
	{
		Selector sel = null;
		try
		{
			sel = SelectorProvider.provider().openSelector();
			socketChannel.register(sel, SelectionKey.OP_READ, this);
			
			while (true) 
			{
				if (sel.select() >= 0) 
				{
					Iterator<SelectionKey> itr = sel.selectedKeys().iterator();
					while (itr.hasNext()) 
					{
						SelectionKey key = itr.next();
						if (key.isReadable())
						{
							 if (conn.getCurrentStatus().isConnected()) 
							 {
								 conn.process();
							 } 
							 else 
							 {
								 conn.disconnect();
							 }
						}
					}
				}
				if (conn.getCurrentStatus().isDisconnected()) 
				{
					break;
				}
			}
			
			logger.debug("[[" + internalCallId + "]] Dialback connection finished, returning result");
			sel.close();
		} 
		catch (IOException e)
		{
			logger.error("Exception in DialbackSession.run", e);
		} 
		catch (StreamException e)
		{
			logger.error("Exception in DialbackSession.run", e);
		}
		catch (Exception e)
		{
			logger.error("Exception in DialbackSession.run", e);
		}
		finally
		{
			try
			{
				sel.close();
			} 
			catch (IOException e)
			{
				logger.error("Exception in DialbackSession.run", e);
			}
		}
		
		// make sure the connection is closed
		try
		{
			conn.disconnect();
		} 
		catch (StreamException e)
		{
			logger.error("Exception in DialbackSession.run", e);
		}

		synchronized (this)
		{
			done = true;
			this.notify();
		}
	}

}
