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
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.jabberstudio.jso.JID;
import org.jabberstudio.jso.StreamContext;

/**
 * This class keeps track of all server to server xmpp connections,
 * there should be one connection to each federated peer
 */

public class SessionManager
{

	static List<Session> sessions = new ArrayList<Session>();
	
	private static int nextInternalCallId = 0;
	
	static Logger logger = Logger.getLogger(SessionManager.class);
	
	public static void addSession(Session session)
	{
		logger.info("Adding connection for destination: " + session.getConnection().getOutboundContext().getTo() + " [[" + session.internalCallId + "]]");
		sessions.add(session);
		logger.info("Adding a session: size after: " + sessions.size() + " [[" + session.internalCallId + "]]");
	}
	
	/**
	 * Gets the non-callback session to be validated
	 * @param destination
	 */
	public static Session getSession(JID destination)
	{
		for (Session sess : sessions)
		{
			StreamContext ctx = sess.getConnection().getOutboundContext();
			if (ctx.getTo() != null && destination.getDomain().equals(ctx.getTo().getDomain()))
			{
				return sess;
			}
		}
		return null;
	}

	public static Session findCreateSession(String from, JID destination)
	{
		logger.info("Finding session for " + destination);
		Session sess = getSession(destination);
		
		if (sess == null)
		{
			try
			{
				logger.debug("Trying to connect to " + destination.getDomain());
				ArrayList<String> dests = DNSHelper.getSRVServerList(destination.getDomain(), "xmpp-server", "tcp");
				logger.debug("Record has " + dests.toString());
				String parts[];
				while (dests.size() > 0)
				{
					String dest = dests.remove(0);
					logger.debug("Record resolves to " + dest);

					if (dest != null)
					{
						parts = dest.split(":");
					}
					else
					{
						// fallback to normal dns if no SRV record
						parts = new String[2];
						parts[0] = destination.getDomain();
						parts[1] = "5269";
					}
					try
					{
						String internalCallId = "SM" + String.format("%08x", nextInternalCallId++);
						InetSocketAddress addr = new InetSocketAddress(parts[0], Integer.parseInt(parts[1]));
						SocketChannel socketChannel = SocketChannel.open();
						socketChannel.socket().connect(addr,5000);
						socketChannel.configureBlocking(false);
						socketChannel.socket().setSoLinger(true, 0);
						logger.debug("Creating session [[" + internalCallId + "]]");
						sess = new Session(internalCallId, from, socketChannel);
					}
					catch (IOException e)
					{
						logger.error("Error connecting to server", e);
						continue;
					}
					break;
				}
				sess.sendDBResult(destination.getDomain());
			} 
			catch (Exception e)
			{
				logger.error("Problem in finding session", e);
			}

		}
		logger.info("Found session [[" + sess.internalCallId + "]]");
		return sess;
	}
	
	public static void removeSession(Session session)
	{
		sessions.remove(session);
		logger.info("Removing a session: size after: " + sessions.size() + " [[" + session.internalCallId + "]]");
	}
}
