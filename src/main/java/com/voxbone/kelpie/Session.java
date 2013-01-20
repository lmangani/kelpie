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
import java.io.InputStream;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;

import javax.sip.address.SipURI;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.jabberstudio.jso.JID;
import org.jabberstudio.jso.JSOImplementation;
import org.jabberstudio.jso.NSI;
import org.jabberstudio.jso.Packet;
import org.jabberstudio.jso.Stream;
import org.jabberstudio.jso.StreamContext;
import org.jabberstudio.jso.StreamElement;
import org.jabberstudio.jso.StreamError;
import org.jabberstudio.jso.StreamException;
import org.jabberstudio.jso.event.PacketEvent;
import org.jabberstudio.jso.event.PacketListener;
import org.jabberstudio.jso.event.StreamStatusEvent;
import org.jabberstudio.jso.event.StreamStatusListener;
import org.jabberstudio.jso.io.src.ChannelStreamSource;
import org.jabberstudio.jso.util.Utilities;


/**
 * Represents an authenticated Server to Server java connection
 * 
 * This class can also manage inbound Dialback challenge requests, 
 * (for chalanges we initate the DialbackSession is used instead)
 * 
 * There is one connection for to each server keplie is federated with (in each direction)
 */
class Session extends Thread implements StreamStatusListener, PacketListener
{

	enum StreamType { RTP, RTCP, VRTP, VRTCP }


	private Stream conn;
	private String host;
	private SocketChannel socketChannel;

	private String sessionKey;
	private boolean confirmed;

	private List<Packet> queue = new LinkedList<Packet>();

	private static String clientName = null;
	private static String clientVersion = null;
	private static String clientPriority;

	private static String fakeId = null;
	private static boolean featVID = true;
	private static boolean featPMUC = true;
	private static boolean featPMUC_UNI = false;
	private static boolean featSMS = false;
	private static boolean featPING = false;
	private static boolean featNICK = false;

	private static boolean useDtmfInfo = false;
	private static int dtmfDuration;

	private static String iconHash;
	private static byte [] iconData;
	private static int iconSize;

	static Logger logger = Logger.getLogger(Session.class);

	public String internalCallId;

	private static String convertToHex(byte [] data) 
	{
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) 
		{
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do 
			{
				if ((0 <= halfbyte) && (halfbyte <= 9))
				{
					buf.append((char) ('0' + halfbyte));
				}
				else
				{
					buf.append((char) ('a' + (halfbyte - 10)));
				}
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();
	}

	static
	{
		MessageDigest md;
		try
		{
 			md = MessageDigest.getInstance("SHA-1");

			byte [] sha1hash = new byte[40];
			byte [] data = new byte[20000];
			InputStream is = Session.class.getResourceAsStream("/icon.jpg");
			iconSize = is.read(data, 0, data.length);
			iconData = new byte[iconSize];
			System.arraycopy(data, 0, iconData, 0, iconSize);
			md.update(iconData);
			sha1hash = md.digest();
			iconHash =  convertToHex(sha1hash);
		} 
		catch (NoSuchAlgorithmException e)
		{

		} 
		catch (IOException e)
		{
			logger.error("Error reading icon", e);
		} 
		catch (Exception e)
		{
			logger.error("Error reading icon", e);
		}
	}
	
	public static void configure(Properties properties)
	{
		clientName = "http://" + properties.getProperty("com.voxbone.kelpie.hostname", "kelpie.voxbone.com") + "/caps";
		clientVersion = "0.2.3";
		clientPriority = properties.getProperty("com.voxbone.kelpie.feature.priority", "24");
		fakeId = properties.getProperty("com.voxbone.kelpie.service_name", "kelpie");
		featVID = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.video", "true"));
		featPMUC = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.pmuc", "true"));
		featPMUC_UNI = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.pmuc.unique", "false"));
		featSMS = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.sms", "false"));
		featPING = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.xmpp-ping", "false"));
		useDtmfInfo = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.dtmf-info", "false"));
		dtmfDuration = Integer.parseInt(properties.getProperty("com.voxbone.kelpie.feature.dtmf-duration", "160"));
		featNICK = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.chat-nickname", "false"));


	}
	
	private long idNum = 0;


	public Session(String internalCallId, String host, SocketChannel sc) throws StreamException 
	{
		this.internalCallId = internalCallId;
		JSOImplementation jso = JSOImplementation.getInstance();
		this.socketChannel = sc;
		this.host = host;
		conn = jso.createStream(Utilities.SERVER_NAMESPACE);
		conn.getOutboundContext().addNamespace("db", "jabber:server:dialback");
		conn.getOutboundContext().setID(Integer.toHexString((int) (Math.random() * 1000000000)));

		conn.addStreamStatusListener(new StatusMonitor(this.internalCallId));
		conn.addStreamStatusListener(this);
		
		conn.addPacketListener(PacketEvent.RECEIVED, this);
		
		conn.connect(new ChannelStreamSource(sc));
		
		start();
	}
	
	public synchronized void sendPacket(Packet p) throws StreamException
	{
		if (!confirmed)
		{
			queue.add(p);
		}
		else
		{
			try
			{
				conn.send(p);
			}
			catch (StreamException e)
			{
				// ignore ...
			}
		}
	}
	
	public void sendDBResult(String to) throws StreamException
	{
		JID local = new JID(host);
		JID remote = new JID(to);

		conn.getOutboundContext().setTo(remote);
		
		SessionManager.addSession(this);

		conn.open();

		Packet p = conn.getDataFactory().createPacketNode(new NSI("result", "jabber:server:dialback"), Packet.class);

		p.setFrom(local);
		p.setTo(remote);
		sessionKey = UUID.randomUUID().toString();

		p.addText(sessionKey);
		conn.send(p);
	}

	public Stream getConnection()
	{
		return conn;
	}
	
	public String getSessionKey()
	{
		return sessionKey;
	}

	public void confirm()
	{
		confirmed = true;
	}
	
	public boolean isConfirmed()
	{
		return confirmed;
	}
	
	public boolean execute() throws Exception
	{
		boolean running = true;
		
		try
		{
			if (conn.getCurrentStatus().isConnected())
			{
				conn.process();
			}
			else
			{
				conn.close();
				conn.disconnect();
			}
		}
		catch (StreamException e)
		{
			// ignore ...
			conn.close();
			conn.disconnect();
		}
		
		if (conn.getCurrentStatus().isDisconnected())
		{
			running = false;
			SessionManager.removeSession(this);
		}
		
		return running;
	}
	
	public void packetTransferred(PacketEvent evt)
	{
		try
		{
			JID local = evt.getData().getTo();
			JID remote = evt.getData().getFrom();

			logger.debug("[[" + internalCallId + "]] got message of " + evt.getData().getQualifiedName());

			if (evt.getData().getQualifiedName().equals("db:result"))
			{
				String type = evt.getData().getAttributeValue("type");
				if (type != null && type.length() > 0)
				{
					synchronized (this)
					{
						confirm();
						while (!queue.isEmpty())
						{
							conn.send(queue.remove(0));
						}
					}
					return;
				}

				String result = evt.getData().normalizeText();
				evt.setHandled(true);

				// this isn't a dialback connection - add it to the list of connections
				// we don't save this because it can only be used for inbound stuff
				//SessionManager.addSession(this);

				logger.debug("[[" + internalCallId + "]] Got a result response: " + evt.getData().normalizeText());
				logger.debug("[[" + internalCallId + "]] Packet is of type: " + evt.getData().getClass().getName());

				DialbackSession dbs = new DialbackSession(internalCallId, local, remote, conn.getOutboundContext().getID(), result);

				boolean valid = dbs.doDialback();
				Packet p = null;
				if (valid)
				{
					logger.debug("[[" + internalCallId + "]] Session is valid!");
					p = conn.getDataFactory().createPacketNode(new NSI("result", "jabber:server:dialback"), Packet.class);
					p.setFrom(local);
					p.setTo(remote);
					p.setAttributeValue("type", "valid");
					confirm();
				}
				else
				{
					logger.debug("[[" + internalCallId + "]] Session is NOT valid!");
					p = conn.getDataFactory().createPacketNode(new NSI("result", "jabber:server:dialback"), Packet.class);
					p.setFrom(local);
					p.setTo(remote);
					p.setAttributeValue("type", "invalid");					
				}

				try
				{
					conn.send(p);
				} 
				catch (StreamException e)
				{
					logger.error("Error sending packet!", e);
				}
				
				if (!valid)
				{
					// close the stream if invalid
					conn.close();
				}
			}
			else if (evt.getData().getQualifiedName().equals("db:verify"))
			{
				String key = evt.getData().normalizeText();
				// if we get a db:verify here and n
				logger.debug("[[" + internalCallId + "]] Got a verification token " + key);
				Session sess = SessionManager.getSession(evt.getData().getFrom());

				boolean valid = false;
				if (sess != null)
				{
					logger.debug("[[" + internalCallId + "]] Found matching session");

					if (key.equals(sess.getSessionKey()))
					{
						logger.debug("[[" + internalCallId + "]] Keys Match! Sending the ok");
						valid = true;
					}
				}

				Packet p;
				if (valid)
				{
					logger.debug("[[" + internalCallId + "]] Session is valid!");
					p = conn.getDataFactory().createPacketNode(new NSI("verify", "jabber:server:dialback"), Packet.class);
					p.setFrom(local);
					p.setTo(remote);
					p.setID(evt.getData().getID());
					p.setAttributeValue("type", "valid");
				}
				else
				{
					logger.debug("[[" + internalCallId + "]] Session is NOT valid!");
					p = conn.getDataFactory().createPacketNode(new NSI("verify", "jabber:server:dialback"), Packet.class);
					p.setFrom(local);
					p.setTo(remote);
					p.setAttributeValue("type", "invalid");					
				}

				try
				{
					conn.send(p);
				} 
				catch (StreamException e)
				{
					logger.error("Steam error in session", e);
				}

			}
			
			else if (   evt.getData().getQualifiedName().equals(":message")
			         && evt.getData().getAttributeValue("type") != null )
			         //&& evt.getData().getAttributeValue("type").equals("chat"))
			{
				if (evt.getData().getAttributeValue("type").equals("error")) {
				 	logger.debug("[[" + internalCallId + "]] got an MESSAGE error ");
				 	// should we notify this error to the sender?
				}
				else if (evt.getData().getAttributeValue("type").equals("chat")) {
				logger.debug("[[" + internalCallId + "]] Got an IM");
				
				StreamElement body = evt.getData().getFirstElement("body");
				if (body != null) 
				{
					String msg = body.normalizeText();
					logger.debug("[[" + internalCallId + "]] Body=" + msg);
	
					MessageMessage mm = new MessageMessage(evt.getData());
	
					if (msg.equals("callback"))
					{
						CallSession cs = new CallSession();
						logger.debug("[[" + internalCallId + "]] created call session : [[" + cs.internalCallId + "]]");
						
						cs.offerPayloads.add(CallSession.PAYLOAD_PCMU);
						cs.offerPayloads.add(CallSession.PAYLOAD_PCMA);
	
						Session sess = SessionManager.findCreateSession(cs.jabberLocal.getDomain(), cs.jabberRemote);
						
						sess.startCall(cs, evt.getData().getTo().getNode(), UriMappings.toSipId(evt.getData().getFrom()));
					}
					
					else if ( msg.toLowerCase().startsWith("/dtmf:") || msg.toLowerCase().startsWith("/dial:") )
					{
						logger.debug("[[" + internalCallId + "]] DIAL command detected");
						CallSession cs = CallManager.getSession(evt.getData().getFrom(), evt.getData().getTo());
						if (cs != null)
						{
							logger.debug("[[" + internalCallId + "]] got call session : [[" + cs.internalCallId + "]]");
							logger.debug("[[" + internalCallId + "]] Call found, sending dtmfs");
							for (int i = "/dial:".length(); i < msg.length(); i++)
							{
								if (useDtmfInfo) {
									SipService.sendDTMFinfo(cs, msg.charAt(i), dtmfDuration);
								} else {
									cs.relay.sendSipDTMF(msg.charAt(i));

								}
							}
						}
					}
					
					else if (msg.equals("/echo") || msg.startsWith("/echo"))
                    {
                            logger.debug("[[" + internalCallId + "]] Got an ECHO request");
                            Packet p = conn.getDataFactory().createPacketNode(new NSI("message", "jabber:server"), Packet.class);

                            p.setFrom(evt.getData().getTo());
                            p.setTo(evt.getData().getFrom());
                            p.setID(evt.getData().getID());
                            p.addElement("body");
                            String echo = msg.substring(msg.lastIndexOf('/') + 5);
                            p.getFirstElement("body").addText("Echo: "+ echo);
                            p.setAttributeValue("type", "chat");
                            p.setAttributeValue("iconset", "round");
                            // initial experiment with chatstates
                            StreamElement chatstate = conn.getDataFactory().createElementNode(new NSI("active", "http://jabber.org/protocol/chatstates"));
                            p.add(chatstate);
                            Session sess = SessionManager.findCreateSession(evt.getData().getTo().getDomain(), evt.getData().getFrom());
                            sess.sendPacket(p);
                    }
					else if (msg.equals("/me") || msg.startsWith("/me"))
                    {
                        
                            String slashme = msg.substring(msg.lastIndexOf('/') + 3);
                            StreamElement newbody = conn.getDataFactory().createElementNode(new NSI("body", slashme));
                            body = newbody;
                            logger.debug("[[" + internalCallId + "]] Got a SLASHME request:");
                            String domain = host;
                        	
    						SipSubscription sub = SipSubscriptionManager.getWatcher(mm.from, mm.to);
    						if (sub != null)
    						{
    							domain = ((SipURI)sub.remoteParty.getURI()).getHost();
    						}
    						SipService.sendMessageMessage(mm, domain);
                           
                    }
					
					else
					{
						/* Forward the message to SIP side */
						/* For coherence, we try to use the domain he has used in his subscription */
						String domain = host;
	
						SipSubscription sub = SipSubscriptionManager.getWatcher(mm.from, mm.to);
						if (sub != null)
						{
							domain = ((SipURI)sub.remoteParty.getURI()).getHost();
						}
						SipService.sendMessageMessage(mm, domain);
					}
				  } 
				}
			   
			} 
			
			else if (evt.getData().getQualifiedName().equals(":presence"))
			{
				logger.debug("[[" + internalCallId + "]] Got presence stanza");
				String type = evt.getData().getAttributeValue("type");

				if (type == null || type.equals("unavailable"))
				{
					logger.debug("[[" + internalCallId + "]] Got a presence message from " + evt.getData().getFrom() );
					
					StreamElement caps = evt.getData().getFirstElement(new NSI("c", "http://jabber.org/protocol/caps"));
					
					if (caps != null && caps.getAttributeValue("ext") != null)
					{
						logger.debug("[[" + internalCallId + "]] Caps found");
						if (caps.getAttributeValue("ext").contains("voice-v1"))
						{
							logger.debug("[[" + internalCallId + "]] Voice support detected, taking note");
							UriMappings.addVoiceResource(evt.getData().getFrom());
						}
						/*
						if (caps.getAttributeValue("ext").contains("video-v1"))
						{
							logger.debug("[[" + internalCallId + "]] Video support detected, not taking note");
						}
						
						if (caps.getAttributeValue("ext").contains("vainvite-v1"))
						{
							logger.debug("[[" + internalCallId + "]] 'vainvite' undocumented feature. Ignored for now. [" + evt.getData().getFrom() + "]" );
						}
						*/
					}
					Presence pres = new Presence(evt.getData());
					String from = UriMappings.toSipId(evt.getData().getFrom());
					String to = evt.getData().getTo().getNode();
					SipSubscription sub = SipSubscriptionManager.getWatcher(from, to);
					if (sub != null)
					{
						logger.debug("[[" + internalCallId + "]] Found matching subscription! Sending NOTIFY");
						sub.sendNotify(false, pres);
					}
				}
				else
				{
					if (type.equals("subscribe"))
					{
						logger.debug("[[" + internalCallId + "]] New subscription received from " + evt.getData().getFrom() );
						String from = UriMappings.toSipId(evt.getData().getFrom());
						String to = evt.getData().getTo().getNode();
						
						if (!to.equals(fakeId))
						{
							SipSubscription sub = SipSubscriptionManager.getSubscription(from, to);
							if (sub == null)
							{
								logger.debug("[[" + internalCallId + "]] No existing subscription, sending one");
								sub = new SipSubscription(from, to);
								SipSubscriptionManager.addSubscriber(from, sub);
								sub.sendSubscribe(false);
							}
							else if (sub.remoteTag != null)
							{
								logger.debug("[[" + internalCallId + "]] Subscription exists, sending refresh");
								sub.sendSubscribe(false);
							}
						}
						else
						{
							logger.debug("[[" + internalCallId + "]] Subscription to " + fakeId + ", sending dummy accept");
							Session sess = SessionManager.findCreateSession(host, evt.getData().getFrom());
							sess.sendSubscribeRequest(new JID(fakeId + "@" + host), evt.getData().getFrom(), "subscribed");
						}
					}
					else if (type.equals("unsubscribe"))
					{
						logger.debug("[[" + internalCallId + "]] Unsubscribe  request");

						String from = UriMappings.toSipId(evt.getData().getFrom());
						String to = evt.getData().getTo().getNode();
						if (!to.equals(fakeId))
						{
							SipSubscription sub = SipSubscriptionManager.removeSubscription(from, to);
							if (sub != null)
							{
								logger.debug("[[" + internalCallId + "]] Removing subscription");
								sub.sendSubscribe(true);
							}
							
							sub = SipSubscriptionManager.getWatcher(from, to);
							if (sub != null)
							{
								logger.debug("[[" + internalCallId + "]] Removing watcher");
								SipSubscriptionManager.removeWatcher(from, sub);
								sub.sendNotify(true, null);
							}
						}
					}
					else if (type.equals("subscribed"))
					{
						logger.debug("[[" + internalCallId + "]] Jabber client accepted subscription, sending notify");
						String from = UriMappings.toSipId(evt.getData().getFrom());
						String to = evt.getData().getTo().getNode();
						if (!to.equals(fakeId))
						{
							SipSubscription sub = SipSubscriptionManager.getWatcher(from, to);
							sub.sendNotify(false, null);
						}
					}
					else if (type.equals("probe"))
					{
						String from = UriMappings.toSipId(evt.getData().getFrom());
						String to = evt.getData().getTo().getNode();
						logger.debug("[[" + internalCallId + "]] Probe received from " + from + " to " + to);
						
						if (!to.equals(fakeId))
						{
							SipSubscription sub = SipSubscriptionManager.getSubscription(from, to);
							if (sub != null)
							{
								logger.debug("[[" + internalCallId + "]] Found a subscription, sending re-subscribe");
								sub.sendSubscribe(false);
							}
							else
							{
								logger.debug("[[" + internalCallId + "]] No Subscription for this person, sending 0 length one");
								sub = new SipSubscription(from, to);
								SipSubscriptionManager.addSubscriber(from, sub);
								sub.sendSubscribe(false);
							}
						}
					}
				}
			}
			else if (evt.getData().getQualifiedName().equals(":iq"))
			{
				Packet packet = evt.getData();
				logger.debug("[[" + internalCallId + "]] got disco packet");
				if (   packet.getAttributeValue("type").equals("get")
				    && packet.getFirstElement().getNSI().equals(new NSI("query", "http://jabber.org/protocol/disco#info")))
				{
					logger.debug("[[" + internalCallId + "]] Got a feature query");
					Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);
					
					p.setFrom(packet.getTo());
					p.setTo(packet.getFrom());
					p.setID(packet.getID());
					p.setAttributeValue("type", "result");
					
					StreamElement query = conn.getDataFactory().createElementNode(new NSI("query", "http://jabber.org/protocol/disco#info"));
					query.setAttributeValue("node", clientName + "#" + clientVersion);
					
					// Google-Centric Feature Set
					
						if (featPMUC) {
							query.addElement("feature").setAttributeValue("var", "http://www.google.com/xmpp/protocol/pmuc/v1");	
						}
						if (featSMS) {
							query.addElement("feature").setAttributeValue("var", "http://www.google.com/xmpp/protocol/pmuc/v1");	
						}
				
						// Voice MUST be enabled
							query.addElement("feature").setAttributeValue("var", "http://www.google.com/xmpp/protocol/voice/v1");
						
						if (featVID) {
							query.addElement("feature").setAttributeValue("var", "http://www.google.com/xmpp/protocol/video/v1");
							query.addElement("feature").setAttributeValue("var", "http://www.google.com/xmpp/protocol/camera/v1");
						}
						
					// General XEP Set
						
						if (featPING) {
							// xep-0199
							query.addElement("feature").setAttributeValue("var", "urn:xmpp:ping");
						}
						
						if (featPMUC && featPMUC_UNI) {
							// xep-0199
							query.addElement("feature").setAttributeValue("var", "http://jabber.org/protocol/muc#unique");
						}

					p.add(query);
					
					Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());
					sess.sendPacket(p);
				}
				
				// XEP-0307 (used in G+ hangouts)
				else if (   packet.getAttributeValue("type").equals("get")
					    && packet.getFirstElement().getNSI().equals(new NSI("unique", "http://jabber.org/protocol/muc#unique")))
					{
					
					Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());

						if (featPMUC && featPMUC_UNI) {
							// Result with UUID
							sess.unIQ(packet);
						} else {
							// Status Unavailable - not required by XEP specification
							// sess.errorIQ(packet, "unavailable");
						}
						
					}
				
				// XEP-0199
				else if (   packet.getAttributeValue("type").equals("get")
						&& packet.getFirstElement().getNSI().equals(new NSI("ping", "urn:xmpp:ping")))
					{
					
					Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());

						if (featPING) {
							// Result Pong
							sess.ackIQ(packet);
						} else {
							// XMPP Ping Not Supported
							sess.cancelIQ(packet);
						}
						
					}
				
				else if ( packet.getAttributeValue("type").equals("error"))
				 {
					logger.debug("[[" + internalCallId + "]] Got error stanza");

						StreamElement error = packet.getFirstElement("error");
							if ( error != null )
							{
								logger.debug("[[" + internalCallId + "]] Error code: " + error.getAttributeValue("code") + " type: " + error.getAttributeValue("type") );
								if (error.getAttributeValue("type") == "cancel") 
								{
									logger.debug("[[" + internalCallId + "]] Sending cancel..." );
									String sessionId = packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getID();
 									CallSession cs = CallManager.getSession(sessionId);
 									if (cs != null) {
									SipService.sendReject(cs);
									logger.debug("[[" + internalCallId + "]] Removing session... " );
		 							CallManager.removeSession(cs);
									}
								} else {  
									logger.debug("[[" + internalCallId + "]] Proceeding... ");
								}
							}
				 }
				
				else if (   packet.getAttributeValue("type").equals("set")
				         && packet.getFirstElement(new NSI("session", "http://www.google.com/session")) != null)
				{
					if (packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("initiate"))
					{
						logger.debug("[[" + internalCallId + "]] Got a request to start a call");
						Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());
						sess.ackIQ(packet);
						
						CallSession cs = new CallSession();
						logger.debug("[[" + internalCallId + "]] created call session : [[" + cs.internalCallId + "]]");
						cs.parseInitiate(packet);
						
						CallManager.addSession(cs);
						
						/* For coherence, we try to use the domain he has used in his subscription */
						String domain = host;

						SipSubscription sub = SipSubscriptionManager.getWatcher(UriMappings.toSipId(cs.jabberRemote), cs.jabberLocal.getNode());
						
						if (sub != null)
						{
							domain = ((SipURI) sub.remoteParty.getURI()).getHost();
						}
						SipService.sendInvite(cs, domain);
					}
					
					else if (packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("transport-info"))
					{
						logger.debug("[[" + internalCallId + "]] Got transport info");
						Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());
						sess.ackIQ(packet);
						
						StreamElement origTransport = packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getFirstElement("transport");
						
						if (origTransport.getNamespaceURI().equals("http://www.google.com/transport/p2p"))
						{
							StreamElement candidate = origTransport.getFirstElement("candidate");
							if (   candidate != null
							    && candidate.getAttributeValue("protocol").equals("udp"))
							{
								String sessionId = packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getID();
								
								CallSession cs = CallManager.getSession(sessionId);
								
								if (cs != null)
								{
									logger.debug("[[" + internalCallId + "]] got call session : [[" + cs.internalCallId + "]]");
									if (!cs.sentTransport)
									{
										sess.sendTransportInfo(cs);
										cs.sentTransport = true;
									}
									sess.acceptTransport(packet);
									
									cs.relay.sendBind(candidate.getAttributeValue("username"), cs.candidateUser, candidate.getAttributeValue("address"), Integer.parseInt(candidate.getAttributeValue("port")), false);
								}
							}
						}
					}
					else if (packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("candidates"))
					{
						logger.debug("[[" + internalCallId + "]] Got candidate");
						Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());
						sess.ackIQ(packet);
						/*StreamElement origTransport = */packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getFirstElement("transport");
						StreamElement session = packet.getFirstElement(new NSI("session", "http://www.google.com/session"));
						for(Object objCandidate : session.listElements("candidate"))
						{
							StreamElement candidate = (StreamElement)objCandidate;

							if (   candidate != null
									&& candidate.getAttributeValue("protocol").equals("udp"))
							{
								String sessionId = session.getID();

								CallSession cs = CallManager.getSession(sessionId);

								if (cs != null)
								{
									logger.debug("[[" + internalCallId + "]] got call session : [[" + cs.internalCallId + "]]");

									if (candidate.getAttributeValue("name").equals("video_rtp")/* || candidate.getAttributeValue("name").equals("video_rtcp")*/)
									{
										if (!cs.sentVTransport)
										{
											sess.sendTransportCandidates(cs, StreamType.VRTP);
										}

										cs.vRelay.sendBind(candidate.getAttributeValue("username"), cs.candidateVUser, candidate.getAttributeValue("address"), Integer.parseInt(candidate.getAttributeValue("port")), false);
									}
									else if (candidate.getAttributeValue("name").equals("video_rtcp"))
									{
										if (!cs.sentVTransport)
										{
											sess.sendTransportCandidates(cs, StreamType.VRTCP);
										}

										cs.vRelay.sendBind(candidate.getAttributeValue("username"), cs.candidateVUser, candidate.getAttributeValue("address"), Integer.parseInt(candidate.getAttributeValue("port")), true);
									}
									else if (candidate.getAttributeValue("name").equals("rtp")/* || candidate.getAttributeValue("name").equals("rtcp")*/)
									{
										if (!cs.sentTransport)
										{
											sess.sendTransportCandidates(cs, StreamType.RTP);
										}

										cs.relay.sendBind(candidate.getAttributeValue("username"), cs.candidateUser, candidate.getAttributeValue("address"), Integer.parseInt(candidate.getAttributeValue("port")), false);
									}
									else if (candidate.getAttributeValue("name").equals("rtcp"))
									{
										if (!cs.sentTransport)
										{
											sess.sendTransportCandidates(cs, StreamType.RTCP);										
										}

										cs.relay.sendBind(candidate.getAttributeValue("username"), cs.candidateUser, candidate.getAttributeValue("address"), Integer.parseInt(candidate.getAttributeValue("port")), true);
									}
								}
							}
						}
					}
					else if (packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("transport-accept"))
					{
						logger.debug("[[" + internalCallId + "]] Got transport accept");
						Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());
						sess.ackIQ(packet);
					}
					else if (packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("accept"))
					{
						logger.debug("[[" + internalCallId + "]] Got transport accept");
						Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());
						sess.ackIQ(packet);						
						CallSession cs = CallManager.getSession(packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getID());
						if (cs != null)
						{
							logger.debug("[[" + internalCallId + "]] got call session : [[" + cs.internalCallId + "]]");
							logger.debug("[[" + internalCallId + "]] Call found sending 200 OK");
							cs.parseAccept(packet);
							SipService.acceptCall(cs);
						}
					}
					else if (packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("terminate"))
					{
						logger.debug("[[" + internalCallId + "]] Got a terminate");
						String sessionId = packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getID();
						CallSession cs = CallManager.getSession(sessionId);
						if (cs != null)
						{
							logger.debug("[[" + internalCallId + "]] got call session : [[" + cs.internalCallId + "]]");
							logger.debug("[[" + internalCallId + "]] found call session, forwarding BYE");
							SipService.sendBye(cs);
							CallManager.removeSession(cs);
						}
					}

					else if ( packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getAttributeValue("type").equals("reject"))
					{
						logger.debug("[[" + internalCallId + "]] Got a reject");
						String sessionId = packet.getFirstElement(new NSI("session", "http://www.google.com/session")).getID();
						CallSession cs = CallManager.getSession(sessionId);						
						if (cs != null)
						{
							logger.debug("[[" + internalCallId + "]] got call session : [[" + cs.internalCallId + "]]");
							logger.debug("[[" + internalCallId + "]] found call session, forwarding reject");
							SipService.sendReject(cs);
							CallManager.removeSession(cs);
						}

					}
				}
				
				else if (   packet.getAttributeValue("type").equals("set")
				         && packet.getFirstElement(new NSI("otr", "http://jabber.org/protocol/archive")) != null)
				{
					logger.debug("[[" + internalCallId + "]] Got a Jabber Archive/Record status change, forwarding.... ");
					
					String otr = "";
					Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);
					p.setFrom(packet.getTo());
					p.setTo(packet.getFrom());
					p.setID(packet.getID());
					
					MessageMessage mm = new MessageMessage(evt.getData());
					
					if (packet.getFirstElement(new NSI("otr", "http://jabber.org/protocol/archive")).getFirstElement("record").getAttributeValue("otr").equals("true") )
					{
						logger.info("[[" + internalCallId + "]] chat session is OFF the records ");
						otr = "Chat session is OFF RECORDS";
					} 
					else if (packet.getFirstElement(new NSI("otr", "http://jabber.org/protocol/archive")).getFirstElement("record").getAttributeValue("otr").equals("false") )
					{
						logger.info("[[" + internalCallId + "]] chat session is RECORDED ");
						otr = "Chat session is RECORDED";
					}
					
                   mm.body = "["+otr+"]";
                   String domain = host;

					SipSubscription sub = SipSubscriptionManager.getWatcher(mm.from, mm.to);
					if (sub != null)
					{
						domain = ((SipURI)sub.remoteParty.getURI()).getHost();
					}
					SipService.sendMessageMessage(mm, domain);
				}
				
				else if (   packet.getAttributeValue("type").equals("get")
				         && packet.getFirstElement().getNSI().equals(new NSI("vCard", "vcard-temp")))
				{
					logger.debug("[[" + internalCallId + "]] Got an ICON request!");
					Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);
					
					p.setFrom(packet.getTo());
					p.setTo(packet.getFrom());
					p.setID(packet.getID());
					p.setAttributeValue("type", "result");

					StreamElement query = conn.getDataFactory().createElementNode(new NSI("vCard", "vcard-temp"));
					
					StreamElement fullName = query.addElement("FN");
					
					//if a telephone number  add a + to be pretty
					if(packet.getTo().getNode().toString().matches("[0-9]+"))
					{
						fullName.addText("+" + packet.getTo().getNode().toString());
					}
					else
					{
						fullName.addText(packet.getTo().getNode().toString());						
					}
					StreamElement photo = query.addElement("PHOTO");
					StreamElement type = photo.addElement("TYPE");
					type.addText("image/jpeg");
					StreamElement binval = photo.addElement("BINVAL");
					byte [] encoded = Base64.encodeBase64Chunked(iconData);
					binval.addText(new String(encoded));
					
					p.add(query);
					
					Session sess = SessionManager.findCreateSession(packet.getTo().getDomain(), packet.getFrom());

					sess.sendPacket(p);
				}
			}
		}
		catch (Exception e)
		{
			logger.error("Exception in packetTransferred", e);
		}
	}

	private void ackIQ(Packet packet) throws StreamException
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);

		p.setFrom(packet.getTo());
		p.setTo(packet.getFrom());
		p.setID(packet.getID());
		p.setAttributeValue("type", "result");
		sendPacket(p);
	}

	private void cancelIQ(Packet packet) throws StreamException
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);
		
		p.setFrom(packet.getTo());
		p.setTo(packet.getFrom());
		p.setID(packet.getID());
		p.setAttributeValue("type", "error");
			StreamElement error = conn.getDataFactory().createElementNode(new NSI("error", "cancel"));
			error.addElement("service-unavailable").setAttributeValue("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
		p.add(error);
		sendPacket(p);
	}
	
	// XEP-0307 Unique MUC 
	private void unIQ(Packet packet) throws StreamException
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);

		p.setFrom(packet.getTo());
		p.setTo(packet.getFrom());
		p.setID(packet.getID());
		p.setAttributeValue("type", "result");
		p.addElement("unique").setAttributeValue("xmlns", "http://jabber.org/protocol/muc#unique");
		p.getFirstElement("unique").setAttributeValue("hangout-id", "Kelpie-hangout");
		String uniq = UUID.randomUUID().toString();
		p.getFirstElement("unique").addText(uniq);
		sendPacket(p);
	}
	
	// error helper
	private void errorIQ(Packet packet, String...type) throws StreamException
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);
		
		p.setFrom(packet.getTo());
		p.setTo(packet.getFrom());
		p.setID(packet.getID());
		p.setAttributeValue("type", "error");
			StreamElement error = conn.getDataFactory().createElementNode(new NSI("error", "cancel"));
			if (type != null) {
				for (int i = 0; i < type.length; i++) {
						if (type[i] == "limit" )
						{
							error.addElement("resource-constraint").setAttributeValue("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
							error.addElement("resource-limit-exceeded").setAttributeValue("xmlns", "urn:xmpperrors");
						}
						else if (type[i] == "unavailable" )
						{
							error.addElement("service-unavailable").setAttributeValue("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
						}
						else if (type[i] == "forbidden") 
						{
							p.getFirstElement("error").setAttributeValue("type", "auth");
							error.addElement("forbidden").setAttributeValue("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
						}
					}
				}
			
		p.add(error);
		sendPacket(p);
	}
	
	public void acceptTransport(Packet origPacket) throws StreamException
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);

		logger.debug("[[" + internalCallId + "]] Accepting a transport");
		
		p.setFrom(origPacket.getTo());
		p.setTo(origPacket.getFrom());
		p.setID(Long.toString(++this.idNum));
		p.setAttributeValue("type", "set");

		StreamElement origSession = origPacket.getFirstElement();
		StreamElement session = p.addElement(new NSI("session", "http://www.google.com/session"));
		session.setAttributeValue("type", "transport-accept");
		session.setID(origSession.getID());
		session.setAttributeValue("initiator", origSession.getAttributeValue("initiator"));
		session.addElement(new NSI("transport", "http://www.google.com/transport/p2p"));

		sendPacket(p);
	}
	
	public boolean sendSubscribeRequest(JID from, JID to, String type)
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("presence", Utilities.SERVER_NAMESPACE), Packet.class);
		p.setFrom(from);
		p.setTo(to);
		p.setAttributeValue("type", type);
		
		if (featNICK && type == "subscribe") {
			String nick = from.toString().split("@")[0];
				if (nick.contains("+")) { nick = nick.split("+")[0]; }
			p.addElement(new NSI("nick", "http://jabber.org/protocol/nick"));
			p.getFirstElement("nick").addText(nick);
		}
		
		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Stream Error sending Subscribe!", e);
			return false;
		}
		return true;
	}
	
	public boolean startCall(CallSession callSession, String from, String to)
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", Utilities.SERVER_NAMESPACE), Packet.class);
		
		callSession.jabberLocal = new JID(from + "@" + host + "/kelpie");
		callSession.jabberRemote = new JID(UriMappings.toJID(to).toString() + "/" + UriMappings.getVoiceResource(UriMappings.toJID(to)));
		callSession.jabberInitiator = callSession.jabberLocal.toString();
		
		callSession.jabberSessionId = Integer.toString((int) (Math.random() * 1000000000));
		
		CallManager.addSession(callSession);
		
		p.setFrom(callSession.jabberLocal);
		p.setTo(callSession.jabberRemote);
		
		p.setID(Long.toString(++this.idNum));
		p.setAttributeValue("type", "set");
		
		StreamElement session = p.addElement(new NSI("session", "http://www.google.com/session"));
		
		session.setAttributeValue("type", "initiate");
		session.setID(callSession.jabberSessionId);
		
		session.setAttributeValue("initiator", callSession.jabberInitiator);
		
		StreamElement description = null;
		if (callSession.vRelay != null)
		{
			description = session.addElement(new NSI("description", "http://www.google.com/session/video"));
			
			for (CallSession.VPayload payload : callSession.offerVPayloads)
			{
				StreamElement payload_type = description.addElement("payload-type");
				
				payload_type.setAttributeValue("id", Integer.toString(payload.id));
				payload_type.setAttributeValue("name", payload.name);
				payload_type.setAttributeValue("width", Integer.toString(payload.width));
				payload_type.setAttributeValue("height", Integer.toString(payload.height));
				payload_type.setAttributeValue("framerate", Integer.toString(payload.framerate));
			}
		}
		else
		{
			description = session.addElement(new NSI("description", "http://www.google.com/session/phone"));
		}
		
		for (CallSession.Payload payload : callSession.offerPayloads)
		{
			StreamElement payload_type = description.addElement("payload-type", "http://www.google.com/session/phone");
			
			payload_type.setAttributeValue("id", Integer.toString(payload.id));
			payload_type.setAttributeValue("clockrate", Integer.toString(payload.clockRate));
			payload_type.setAttributeValue("bitrate", Integer.toString(payload.bitRate));
			payload_type.setAttributeValue("name", payload.name);
		}
		
		/*StreamElement transport = */session.addElement(new NSI("transport", "http://www.google.com/transport/p2p"));

		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Stream error in startCall", e);
			return false;
		}

		if (callSession.vRelay != null)
		{
			callSession.sentTransport = true;
			callSession.sentVTransport = true;
			sendTransportCandidates(callSession, StreamType.RTCP);
			sendTransportCandidates(callSession, StreamType.RTP);
			sendTransportCandidates(callSession, StreamType.VRTCP);
			sendTransportCandidates(callSession, StreamType.VRTP);
		}
		else
		{
			callSession.sentTransport = true;
			sendTransportInfo(callSession);
		}

		return true;
	}

	private boolean sendTransportInfo(CallSession callSession)
	{
		Packet p;
		StreamElement session;
		StreamElement transport;
		p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);

		p.setFrom(callSession.jabberLocal);
		p.setTo(callSession.jabberRemote);
		p.setID(Long.toString(++this.idNum));
		p.setAttributeValue("type", "set");
		
		Random r = new Random();
		byte [] bytes = new byte[4];
		r.nextBytes(bytes);
		
		callSession.candidateUser = String.format("%02x%02x%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3]);

		session = p.addElement(new NSI("session", "http://www.google.com/session"));
		session.setAttributeValue("type", "transport-info");
		session.setID(callSession.jabberSessionId);
		session.setAttributeValue("initiator", callSession.jabberInitiator);
		
		transport = session.addElement(new NSI("transport", "http://www.google.com/transport/p2p"));
		
		StreamElement candidate = transport.addElement("candidate");
		candidate.setAttributeValue("name", "rtp");
		candidate.setAttributeValue("address", SipService.getLocalIP());
		candidate.setAttributeValue("port", Integer.toString(callSession.relay.getJabberPort()));
		candidate.setAttributeValue("preference", "1");
		candidate.setAttributeValue("username", callSession.candidateUser);
		candidate.setAttributeValue("password", callSession.candidateUser);
		candidate.setAttributeValue("protocol", "udp");
		
		candidate.setAttributeValue("generation", "0");
		candidate.setAttributeValue("type", "local");
		candidate.setAttributeValue("network", "0");
		
		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error while sending TransportInfo", e);
			return false;
		}
		return true;
	}
	
	private boolean sendTransportCandidates(CallSession callSession, StreamType type)
	{
		Packet p;
		StreamElement session;
		
		Random r = new Random();
		byte [] bytes = new byte[4];
		r.nextBytes(bytes);
		
		if (type == StreamType.RTP || type == StreamType.RTCP)
		{
			if (callSession.candidateUser == null)
			{
				callSession.candidateUser = String.format("%02x%02x%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3]);
			}
			
			p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);

			p.setFrom(callSession.jabberLocal);
			p.setTo(callSession.jabberRemote);
			p.setID(Long.toString(++this.idNum));
			p.setAttributeValue("type", "set");

			session = p.addElement(new NSI("session", "http://www.google.com/session"));
			session.setAttributeValue("type", "candidates");
			session.setID(callSession.jabberSessionId);
			session.setAttributeValue("initiator", callSession.jabberInitiator);

			StreamElement candidate = session.addElement("candidate");
			if (type == StreamType.RTP)
			{
				candidate.setAttributeValue("name", "rtp");
				candidate.setAttributeValue("address", SipService.getLocalIP());
				candidate.setAttributeValue("port", Integer.toString(callSession.relay.getJabberPort()));
			}
			else
			{
				candidate.setAttributeValue("name", "rtcp");
				candidate.setAttributeValue("address", SipService.getLocalIP());
				candidate.setAttributeValue("port", Integer.toString(callSession.relay.getJabberRtcpPort()));
			}
			candidate.setAttributeValue("preference", "1");
			candidate.setAttributeValue("username", callSession.candidateUser);
			candidate.setAttributeValue("password", callSession.candidateUser);
			candidate.setAttributeValue("protocol", "udp");

			candidate.setAttributeValue("generation", "0");
			candidate.setAttributeValue("type", "local");
			candidate.setAttributeValue("network", "0");

			try
			{
				sendPacket(p);
			} 
			catch (StreamException e)
			{
				logger.error("[[" + internalCallId + "]] Error while sending audio TransportCandidates", e);
				return false;
			}
		}
		else if (type == StreamType.VRTP || type == StreamType.VRTCP)
		{
			if (callSession.candidateVUser == null)
			{
				callSession.candidateVUser = String.format("%02x%02x%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3]);
			}
			
			p = conn.getDataFactory().createPacketNode(new NSI("iq", "jabber:server"), Packet.class);

			p.setFrom(callSession.jabberLocal);
			p.setTo(callSession.jabberRemote);
			p.setID(Long.toString(++this.idNum));
			p.setAttributeValue("type", "set");

			session = p.addElement(new NSI("session", "http://www.google.com/session"));
			session.setAttributeValue("type", "candidates");
			session.setID(callSession.jabberSessionId);
			session.setAttributeValue("initiator", callSession.jabberInitiator);

			StreamElement candidate = session.addElement("candidate");
			if (type == StreamType.VRTP)
			{
				candidate.setAttributeValue("name", "video_rtp");
				candidate.setAttributeValue("address", SipService.getLocalIP());
				candidate.setAttributeValue("port", Integer.toString(callSession.vRelay.getJabberPort()));
			}
			else
			{
				candidate.setAttributeValue("name", "video_rtcp");
				candidate.setAttributeValue("address", SipService.getLocalIP());
				candidate.setAttributeValue("port", Integer.toString(callSession.vRelay.getJabberRtcpPort()));				
			}
			candidate.setAttributeValue("preference", "1");
			candidate.setAttributeValue("username", callSession.candidateVUser);
			candidate.setAttributeValue("password", callSession.candidateVUser);
			candidate.setAttributeValue("protocol", "udp");

			candidate.setAttributeValue("generation", "0");
			candidate.setAttributeValue("type", "local");
			candidate.setAttributeValue("network", "0");

			try
			{
				sendPacket(p);
			}
			catch (StreamException e)
			{
				logger.error("[[" + internalCallId + "]] Error while sending video TransportCandidates", e);
				return false;
			}
		}
		return true;
	}
	
	public boolean sendAccept(CallSession callSession)
	{
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", Utilities.SERVER_NAMESPACE), Packet.class);
		
		p.setFrom(callSession.jabberLocal);
		p.setTo(callSession.jabberRemote);
		
		p.setID(Long.toString(++this.idNum));
		p.setAttributeValue("type", "set");

		StreamElement session = p.addElement(new NSI("session", "http://www.google.com/session"));
		
		session.setAttributeValue("type", "accept");
		session.setID(callSession.jabberSessionId);
		
		session.setAttributeValue("initiator", callSession.jabberInitiator);
	
		StreamElement description = null;
		if (callSession.vRelay != null)
		{
			description = session.addElement(new NSI("description", "http://www.google.com/session/video"));
			
			for (CallSession.VPayload payload : callSession.answerVPayloads)
			{
				StreamElement payload_type = description.addElement("payload-type");
				
				payload_type.setAttributeValue("id", Integer.toString(payload.id));
				payload_type.setAttributeValue("name", payload.name);
				
				payload_type.setAttributeValue("width", Integer.toString(payload.width));
				payload_type.setAttributeValue("height", Integer.toString(payload.height));
				payload_type.setAttributeValue("framerate", Integer.toString(payload.framerate));
				
				payload_type.setAttributeValue("clockrate", Integer.toString(payload.clockRate));
			}
		}
		else
		{
			description = session.addElement(new NSI("description", "http://www.google.com/session/phone"));
		}
		
		for (CallSession.Payload payload : callSession.answerPayloads)
		{
			StreamElement payload_type = description.addElement("payload-type", "http://www.google.com/session/phone");
			
			payload_type.setAttributeValue("id", Integer.toString(payload.id));
			payload_type.setAttributeValue("clockrate", Integer.toString(payload.clockRate));
			payload_type.setAttributeValue("bitrate", Integer.toString(payload.bitRate));
			payload_type.setAttributeValue("name", payload.name);
		}
		
		/*StreamElement transport = */session.addElement(new NSI("transport", "http://www.google.com/transport/p2p"));

		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error sending accept", e);
			return false;
		}
		return true;
	}
	
	public boolean sendBye(CallSession callSession)
	{
		CallManager.removeSession(callSession);
		Packet p = conn.getDataFactory().createPacketNode(new NSI("iq", Utilities.SERVER_NAMESPACE), Packet.class);
		
		p.setFrom(callSession.jabberLocal);
		p.setTo(callSession.jabberRemote);
		
		p.setID(Long.toString(++this.idNum));
		p.setAttributeValue("type", "set");
		
		StreamElement session = p.addElement(new NSI("session", "http://www.google.com/session"));
		
		session.setAttributeValue("type", "terminate");
		session.setID(callSession.jabberSessionId);
		
		session.setAttributeValue("initiator", callSession.jabberInitiator);
		
		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error sending BYE", e);
			return false;
		}
		return true;
	}
	
	public boolean sendPresence(Presence pres)
	{
		if (pres == null)
		{
			return false;
		}
		
		Packet p = conn.getDataFactory().createPacketNode(new NSI("presence", Utilities.SERVER_NAMESPACE), Packet.class);

		if (pres.type != null && pres.type.equals("closed"))
		{
			p.setAttributeValue("type", "unavailable");
		}
		
		JID from;
		if (pres.resource != null)
		{
			from = new JID(pres.from + "@" + host + "/" + pres.resource);
		}
		else
		{
			from = new JID(pres.from + "@" + host);
		}
		
		JID to = UriMappings.toJID(pres.to);

		p.setFrom(from);
		p.setTo(to);
		
		StreamElement caps = conn.getDataFactory().createElementNode(new NSI("c", "http://jabber.org/protocol/caps"));
		String features_ext = "voice-v1";
		
		if (featSMS) {
			features_ext = "sms-v1 " + features_ext;
		}
		
		if (featPMUC) {
			features_ext = "pmuc-v1 " + features_ext;
		}
		if (featVID) {
			features_ext = features_ext + " video-v1 camera-v1";
		}
		
		caps.setAttributeValue("ext", features_ext);
		caps.setAttributeValue("node", clientName);
		caps.setAttributeValue("ver", clientVersion);
		p.add(caps);
		
		if (pres.show != null)
		{
			StreamElement show =  conn.getDataFactory().createElementNode(new NSI("show", Utilities.SERVER_NAMESPACE));
			show.addText(pres.show);
			p.add(show);
		}
		
		if (pres.note != null)
		{
			StreamElement status =  conn.getDataFactory().createElementNode(new NSI("status", Utilities.SERVER_NAMESPACE));
			status.addText(pres.note);
			p.add(status);
		}

		if (pres.resource != null && pres.resource.equals("KelpiePhone"))
		{
			StreamElement priority =  conn.getDataFactory().createElementNode(new NSI("priority", Utilities.SERVER_NAMESPACE));
			priority.addText(clientPriority);
			p.add(priority);
		}
		else
		{
			StreamElement priority =  conn.getDataFactory().createElementNode(new NSI("priority", Utilities.SERVER_NAMESPACE));
			priority.addText("1");
			p.add(priority);
		}

		StreamElement vCard = conn.getDataFactory().createElementNode(new NSI("x", "vcard-temp:x:update"));
		StreamElement photo = vCard.addElement("photo");
		photo.addText(iconHash);

		p.add(vCard);
		
		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error sending presence", e);
			return false;
		}

		if (pres.resource != null && !pres.resource.equals("KelpiePhone"))
		{
			p = conn.getDataFactory().createPacketNode(new NSI("presence", Utilities.SERVER_NAMESPACE), Packet.class);

			p.setAttributeValue("type", "unavailable");

			from = new JID(pres.from + "@" +host + "/KelpiePhone");
			p.setFrom(from);
			p.setTo(to);
			
			try
			{
				sendPacket(p);
			} 
			catch (StreamException e)
			{
				logger.error("[[" + internalCallId + "]] Error sending presence", e);
				return false;
			}
		}
		return true;
	}

	public boolean sendMessageMessage(MessageMessage mm)
	{
		JID from = new JID(mm.from + "@" + host);
		JID to = UriMappings.toJID(mm.to);
		
		if (to == null)
		{
			logger.error("[[" + internalCallId + "]] No mapping for to destination : " + mm.to);
			return false;
		}
		
		Packet p = conn.getDataFactory().createPacketNode(new NSI("message", Utilities.SERVER_NAMESPACE), Packet.class);
		p.setFrom(from);
		p.setTo(to);
		p.addElement("body");
		p.getFirstElement("body").addText(mm.body);
		
		p.setAttributeValue("type", "chat");
		
		if (featNICK) {
			String nick = from.toString().split("@")[0];
				if (nick.contains("+")) { nick = nick.split("+")[0]; }
			p.addElement(new NSI("nick", "http://jabber.org/protocol/nick"));
			p.getFirstElement("nick").addText(nick);
		}
		
		if (mm.subject != null)
		{
			p.addElement("subject");
			p.getFirstElement("subject").addText(mm.subject);
		}
		
		if (mm.thread != null)
		{
			p.addElement("thread");
			p.getFirstElement("thread").addText(mm.thread);
		}

		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error sending IM", e);
			return false;
		}
		return true;
	}
	
	// XEP-0224
	public boolean sendMessageHeadline(MessageMessage mm)
	{
		JID from = new JID(mm.from + "@" + host);
		JID to = UriMappings.toJID(mm.to);
		
		if (to == null)
		{
			logger.error("[[" + internalCallId + "]] No mapping for destination : " + mm.to);
			return false;
		}
		
		Packet p = conn.getDataFactory().createPacketNode(new NSI("message", Utilities.SERVER_NAMESPACE), Packet.class);
		p.setFrom(from);
		p.setTo(to);
		p.setAttributeValue("type", "headline");

		p.addElement(new NSI("attention", "urn:xmpp:attention:0"));
		p.addElement("body");
		p.getFirstElement("body").addText(mm.body);
		
		try
		{
			sendPacket(p);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error sending HEADLINE", e);
			return false;
		}
		return true;
	}
	
	public void statusChanged(StreamStatusEvent evt) 
	{
		Stream conn = evt.getStream();
		StreamContext ctx = evt.getContext();
		
		try 
		{
			if (ctx.isInbound()) 
			{
				if (evt.getNextStatus() == Stream.OPENED) 
				{
					// Finish opening
					String ns = conn.getDefaultNamespace();
					
					conn.getOutboundContext().setFrom(new JID(host));
					conn.open();
					
					// Validate name
					if (logger.isDebugEnabled())
					{
						logger.debug("[[" + internalCallId + "]] namespace == " + ns);
					}
					if (ctx.getNamespaceByURI(ns) == null) 
					{
						StreamError err = ctx.getDataFactory().createStreamError(StreamError.INVALID_NAMESPACE_CONDITION);
						
						conn.close(new StreamException(err));
					}
				} 
				else if (evt.getNextStatus() == Stream.CLOSED || evt.getNextStatus() == Stream.DISCONNECTED) 
				{
					// Finish disconnecting
					conn.close();
				}
			} 
			else if (ctx.isOutbound()) 
			{
				if (evt.getPreviousStatus() == Stream.OPENED && evt.getNextStatus() == Stream.CLOSED) 
				{
					conn.disconnect();
				}
			}
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error changing status", e);
		}
	}
	
	public void run()
	{
		Selector sel = null;
		
		logger.info("[[" + internalCallId + "]] Session thread started: " + this.socketChannel.socket().toString());
		
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
						itr.remove();
						if (key.isReadable())
						{
							this.execute();
						}
					}
				}
				else
				{
					logger.error("[[" + internalCallId + "]] Select returned error");
				}
				if (conn.getCurrentStatus().isDisconnected()) 
				{
					break;
				}
			}
			
			logger.info("[[" + internalCallId + "]] Session Connection finished: " + this.socketChannel.socket().toString());
			sel.close();
		} 
		catch (IOException e)
		{
			logger.error("[[" + internalCallId + "]] Error in xmpp session thread", e);
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Error in xmpp session thread", e);
		} 
		catch (Exception e)
		{
			logger.error("[[" + internalCallId + "]] Error in xmpp session thread", e);
		}
		finally
		{
			try
			{
				if (sel != null)
				{
					sel.close();
				}
			} 
			catch (IOException e)
			{
				// we are dead already, RIP
			}
		}
		
		// make sure the connection is closed
		try
		{
			conn.close();
			conn.disconnect();
			try 
			{
				socketChannel.socket().shutdownInput();
			}
			catch (IOException e) 
			{
				// ignore
			}
			try 
			{
				socketChannel.socket().shutdownOutput();
			}
			catch (IOException e) 
			{
				// ignore
			}
			try 
			{
				socketChannel.close();
			}
			catch (IOException e) 
			{
				// ignore
			}
		} 
		catch (StreamException e)
		{
			logger.error("[[" + internalCallId + "]] Problem closing stream", e);
		}
	}

}
