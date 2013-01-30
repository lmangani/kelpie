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


import gov.nist.javax.sip.header.Require;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.Properties;
import java.text.ParseException;

import javax.sip.ClientTransaction;
import javax.sip.Dialog;
import javax.sip.DialogTerminatedEvent;
import javax.sip.IOExceptionEvent;
import javax.sip.InvalidArgumentException;
import javax.sip.ListeningPoint;
import javax.sip.RequestEvent;
import javax.sip.ResponseEvent;
import javax.sip.ServerTransaction;
import javax.sip.SipException;
import javax.sip.SipListener;
import javax.sip.SipProvider;
import javax.sip.TimeoutEvent;
import javax.sip.TransactionAlreadyExistsException;
import javax.sip.TransactionTerminatedEvent;
import javax.sip.TransactionUnavailableException;
import javax.sip.address.Address;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.ContactHeader;
import javax.sip.header.ContentTypeHeader;
import javax.sip.header.ExpiresHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.Header;
import javax.sip.header.ViaHeader;
import javax.sip.header.SubscriptionStateHeader;
import javax.sip.header.ToHeader;
import javax.sip.message.Request;
import javax.sip.message.Response;

import org.apache.log4j.Logger;
import org.jabberstudio.jso.JID;
import org.xml.sax.SAXException;

/**
 * Handles incoming sip requests/responses
 *
 */
public class KelpieSipListener implements SipListener
{

	Logger logger = Logger.getLogger(this.getClass());

	String host;
	
	private static boolean optionsmode = false;
	private static boolean subscribeRport = false;
	private static boolean subscribeEmu = false;


	
	public static void configure(Properties properties)
	{
		optionsmode = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.options.probe", "false"));
		subscribeRport = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.subscribe.rport", "false"));
		subscribeEmu = Boolean.parseBoolean(properties.getProperty("com.voxbone.kelpie.feature.subscribe.force-emu", "false"));

	}
	
	public KelpieSipListener(String host)
	{
		this.host = host;
	}
	
	public void processDialogTerminated(DialogTerminatedEvent evt)
	{

	}

	public void processIOException(IOExceptionEvent evt)
	{

	}

	public void processRequest(RequestEvent evt)
	{
		Request req = evt.getRequest();
		logger.debug("[[SIP]] Got a request " + req.getMethod());
		try
		{
			if (req.getMethod().equals(Request.MESSAGE))
			{
				logger.info("[[SIP]] Forwarding message");
				MessageMessage mm = new MessageMessage(req);
				JID destination = UriMappings.toJID(mm.to);

				ContentTypeHeader cth = (ContentTypeHeader) req.getHeader(ContentTypeHeader.NAME);
				
				if (   !cth.getContentType().equals("text")
				    && !cth.getContentSubType().equals("plain"))
				{
					logger.warn("[[SIP]] Message isn't text, rejecting");
					Response res = SipService.messageFactory.createResponse(Response.NOT_IMPLEMENTED, req);
					
					if (evt.getServerTransaction() == null)
					{
						ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
						tx.sendResponse(res);
					}
					else
					{
						evt.getServerTransaction().sendResponse(res);
					}
					return;					
				}
				
				if (mm.body.startsWith("/echo")) {
					
                    mm.body = mm.body.substring(mm.body.lastIndexOf('/') + 5);
                    mm.to = mm.from;
                    String domain = host;

                    SipSubscription sub = SipSubscriptionManager.getWatcher(mm.from, mm.to);
                    if (sub != null)
                    {
                            domain = ((SipURI)sub.remoteParty.getURI()).getHost();
                    }
                    // logger.debug("[[SIP]] Echo message: " + mm.body);
                    SipService.sendMessageMessage(mm, domain);
                    return;

				} else if (mm.body.startsWith("/me")) {
				
	                mm.body = mm.from + " " + mm.body.substring(mm.body.lastIndexOf('/') + 3);

                }
				
				logger.debug("[[SIP]] Jabber destination is " + destination);
				
				Session sess = SessionManager.findCreateSession(host, destination);

				if (sess != null)
				{
					if (sess.sendMessageMessage(mm))
					{
						logger.debug("[[SIP]] Message forwarded ok");
						Response res = SipService.messageFactory.createResponse(Response.OK, req);
						if (evt.getServerTransaction() == null)
						{
							ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
							tx.sendResponse(res);
						}
						else
						{
							evt.getServerTransaction().sendResponse(res);
						}
						return;
					}
				}

				logger.error("[[SIP]] Forwarding failed!");
			}
			else if (req.getMethod().equals(Request.SUBSCRIBE))
			{
				logger.info("[[SIP]] Received a Subscribe message");
				
				String callid = ((CallIdHeader) req.getHeader(CallIdHeader.NAME)).getCallId();
				FromHeader fh = (FromHeader) req.getHeader("From");
				URI ruri = req.getRequestURI();
				
				String src = ((SipURI) fh.getAddress().getURI()).getUser();
				String dest = ((SipURI) ruri).getUser();
				SipSubscription sub = SipSubscriptionManager.getWatcherByCallID(dest, callid);
				
				if (subscribeRport) {
	               // ContactHeader contact = (ContactHeader) req.getHeader(ContactHeader.NAME);
	               ViaHeader viaHeaderr = (ViaHeader)req.getHeader(ViaHeader.NAME);
	               int rport = Integer.parseInt( viaHeaderr.getParameter("rport") );
	               String received = viaHeaderr.getParameter("received");
	               logger.debug("[[SIP]] Forcing Contact RPORT: "+received+":"+rport);
	               Address localrAddress = SipService.addressFactory.createAddress("sip:" + src + "@" + received + ":" + rport );
	               ContactHeader nch = SipService.headerFactory.createContactHeader(localrAddress);
	               req.removeHeader("Contact");
	               req.addHeader(nch);
				}

				ToHeader th = (ToHeader) req.getHeader("To");
				
				int expires = ((ExpiresHeader) req.getHeader(ExpiresHeader.NAME)).getExpires();

				Response res = SipService.messageFactory.createResponse(Response.ACCEPTED, req);
				
				if (expires > 0)
				{
					logger.debug("[[SIP]] New subscription or refresh");
					if (sub == null)
					{
						if (th.getTag() == null)
						{
							logger.info("[[SIP]] New Subscription, sending add request to user");
							sub = new SipSubscription(req);
							//sub.localTag = ((ToHeader) res.getHeader(ToHeader.NAME)).getTag();
							((ToHeader) res.getHeader(ToHeader.NAME)).setTag(sub.localTag);
							SipSubscriptionManager.addWatcher(dest, sub);

							JID destination = UriMappings.toJID(dest);
							JID source = new JID(src + "@" + host);

							if (destination != null)
							{
								Session sess = SessionManager.findCreateSession(host, destination);
								sess.sendSubscribeRequest(source, destination, "subscribe");
							}
							else
							{
								logger.warn("[[SIP]] Unknown Jabber user...");
								res = SipService.messageFactory.createResponse(Response.NOT_FOUND, req);
							}
						}
						else
						{
							logger.warn("[[SIP]] Rejecting Unknown in-dialog subscribe for "+ ruri);
							res = SipService.messageFactory.createResponse(481, req);
						}
					}
					else
					{
						logger.debug("[[SIP]] Refresh subscribe, sending poll");

						JID destination = UriMappings.toJID(dest);
						JID source = new JID(src + "@" + host);
						
						if (destination != null)
						{
							Session sess = SessionManager.findCreateSession(host, destination);
							sess.sendSubscribeRequest(source, destination, "probe");
						}
						else
						{
							res = SipService.messageFactory.createResponse(Response.NOT_FOUND, req);
							logger.error("[[SIP]] Unknown destination!");
						}
					}
				}
				else
				{
					logger.debug("[[SIP]] Expire subscribe");
					
					if (sub != null)
					{
						logger.debug("[[SIP]] Subscription found, removing");
						sub.sendNotify(true, null);
						SipSubscriptionManager.removeWatcher(dest, sub);
						
						JID destination = UriMappings.toJID(dest);
						JID source = new JID(src + "@" + host);
						
						Session sess = SessionManager.findCreateSession(host, destination);
						sess.sendSubscribeRequest(source, destination, "unsubscribe");
					}
				}
				
				res.addHeader(req.getHeader(ExpiresHeader.NAME));
				
				ListeningPoint lp = SipService.sipProvider.getListeningPoint(ListeningPoint.UDP);
				
				Address localAddress = SipService.addressFactory.createAddress("sip:" + dest + "@" + lp.getIPAddress() + ":" + lp.getPort());
				
				ContactHeader ch = SipService.headerFactory.createContactHeader(localAddress);
				res.addHeader(ch);
				
				if (evt.getServerTransaction() == null)
				{
					ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
					tx.sendResponse(res);
				}
				else
				{
					evt.getServerTransaction().sendResponse(res);
				}

				return;
			}
			else if (req.getMethod().equals(Request.NOTIFY))
			{
				logger.info("[[SIP]] Received a Notify message");
				
				try
				{
					String callid = ((CallIdHeader) req.getHeader(CallIdHeader.NAME)).getCallId();
					FromHeader fh = (FromHeader) req.getHeader("From");
					URI ruri = req.getRequestURI();
					String src = ((SipURI) fh.getAddress().getURI()).getUser();
					String dest = ((SipURI) ruri).getUser();
					SipSubscription sub = SipSubscriptionManager.getSubscriptionByCallID(dest, callid);

					if (sub != null)
					{
						logger.debug("[[SIP]] Subscription found!");
						SubscriptionStateHeader ssh = (SubscriptionStateHeader) req.getHeader(SubscriptionStateHeader.NAME);
						if (ssh.getState().equalsIgnoreCase(SubscriptionStateHeader.PENDING))
						{
							logger.debug("[[SIP]] Subscription pending. Updating");
							sub.updateSubscription(req);
						}
						else if (   ssh.getState().equalsIgnoreCase(SubscriptionStateHeader.ACTIVE)
						         && !sub.isActive())
						{
							logger.debug("[[SIP]] Subscription accepted. Informing");					

							sub.updateSubscription(req);
							JID destination = UriMappings.toJID(dest);
							JID source = new JID(src + "@" + host);

							sub.makeActive();

							Session sess = SessionManager.findCreateSession(host, destination);
							sess.sendSubscribeRequest(source, destination, "subscribed");
						}
						else if (ssh.getState().equalsIgnoreCase(SubscriptionStateHeader.TERMINATED))
						{
							logger.debug("[[SIP]] Subscription is over, removing");
							SipSubscriptionManager.removeSubscriptionByCallID(dest, sub.callId);

							JID destination = UriMappings.toJID(dest);
							@SuppressWarnings("unused")
							JID source = new JID(src + "@" + host);
							
							Session sess = SessionManager.findCreateSession(host, destination);
							sess.sendPresence(Presence.buildOfflinePresence(src, dest));
							
							logger.debug("[[SIP]] Reason code is " + ssh.getReasonCode());
							if (   ssh.getReasonCode() != null
							    && (   ssh.getReasonCode().equalsIgnoreCase(SubscriptionStateHeader.TIMEOUT)
							        || ssh.getReasonCode().equalsIgnoreCase(SubscriptionStateHeader.DEACTIVATED)))
							{
								logger.debug("[[SIP]] Reason is timeout, sending re-subscribe");
								sub = new SipSubscription(dest, src);
								SipSubscriptionManager.addSubscriber(dest, sub);
								sub.sendSubscribe(false);
							}
						}

						if (req.getRawContent() != null)
						{
							try
							{
								Presence pres = new Presence(req);
								JID destination = UriMappings.toJID(dest);
								Session sess = SessionManager.findCreateSession(host, destination);
								sess.sendPresence(pres);
							} 
							catch (UnsupportedEncodingException e)
							{
								logger.error("[[SIP]] Error parsing presence document!\n" + req.toString(), e);
							} 
							catch (SAXException e)
							{
								logger.error("[[SIP]] Error parsing presence document!\n" + req.toString(), e);
							} 
							catch (IOException e)
							{
								logger.error("[[SIP]] Error parsing presence document!\n" + req.toString(), e);
							}
						}
						else if (sub.isActive())
						{
							Presence pres = Presence.buildUnknownPresence(src, dest, host);
							JID destination = UriMappings.toJID(dest);
							Session sess = SessionManager.findCreateSession(host, destination);
							sess.sendPresence(pres);
						}
						
						Response res = SipService.messageFactory.createResponse(Response.OK, req);
						ListeningPoint lp = SipService.sipProvider.getListeningPoint(ListeningPoint.UDP);

						Address localAddress = SipService.addressFactory.createAddress("sip:" + dest + "@" + lp.getIPAddress() + ":" + lp.getPort());

						ContactHeader ch = SipService.headerFactory.createContactHeader(localAddress);
						res.addHeader(ch);

						if (evt.getServerTransaction() == null)
						{
							ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
							tx.sendResponse(res);
						}
						else
						{
							evt.getServerTransaction().sendResponse(res);
						}
					}
					else
					{
						Response res = SipService.messageFactory.createResponse(481, req);
						ListeningPoint lp = SipService.sipProvider.getListeningPoint(ListeningPoint.UDP);

						Address localAddress = SipService.addressFactory.createAddress("sip:" + dest + "@" + lp.getIPAddress() + ":" + lp.getPort());

						ContactHeader ch = SipService.headerFactory.createContactHeader(localAddress);
						res.addHeader(ch);

						if (evt.getServerTransaction() == null)
						{
							ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
							tx.sendResponse(res);
						}
						else
						{
							evt.getServerTransaction().sendResponse(res);
						}
					}
				}
				catch (Exception e)
				{
					logger.error("[[SIP]] failure while handling NOTIFY message", e);
				}

				return;
			}			
			else if (req.getMethod().equals(Request.INVITE))
			{
				if (evt.getDialog() == null)
				{
					logger.info("[[SIP]] Got initial invite!");
					FromHeader fh = (FromHeader) req.getHeader("From");
					URI ruri = req.getRequestURI();
					
					String src = ((SipURI) fh.getAddress().getURI()).getUser();
					String dest = ((SipURI) ruri).getUser();
					
					JID destination = UriMappings.toJID(dest);
					if (destination != null)
					{
						logger.debug("[[SIP]] Attempting to send to destination: " + destination.toString());
						
						ServerTransaction trans;
						if (evt.getServerTransaction() == null)
						{
							trans = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
						}
						else
						{
							trans = evt.getServerTransaction();
						}
						
						Dialog dialog = SipService.sipProvider.getNewDialog(trans);
						Session sess = SessionManager.findCreateSession(host, destination);
						CallSession cs = new CallSession();
						logger.info("[[SIP]] created call session : [[" + cs.internalCallId + "]]");
						cs.parseInvite(req, dialog, trans);
						dialog.setApplicationData(cs);
						if (sess.startCall(cs, src, dest))
						{
							Response res = SipService.messageFactory.createResponse(Response.RINGING, req);
							trans.sendResponse(res);
							return;
						}
					}
				} else {
					// SIP RE-INVITE (dumbstart implementation, ignores timers, etc)
					logger.info("[[SIP]] Got a re-invite!");
					CallSession cs = (CallSession) evt.getDialog().getApplicationData();
					if (cs != null) 
					{
						Response res = null;
						Session sess = SessionManager.findCreateSession(cs.jabberLocal.getDomain(), cs.jabberRemote);
						if (sess == null) 
						{
							res = SipService.messageFactory.createResponse(488, req);
						} else {
							res = SipService.messageFactory.createResponse(Response.CALL_OR_TRANSACTION_DOES_NOT_EXIST, req);
						}
						
						if (evt.getServerTransaction() == null)
							{
								ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
								tx.sendResponse(res);
							}
						else
							{
								evt.getServerTransaction().sendResponse(res);
							}
						return;

					}
				}
			}
			else if (req.getMethod().equals(Request.BYE))
			{
				if (evt.getDialog() != null)
				{
					logger.info("[[SIP]] Got in dialog bye");
					CallSession cs = (CallSession) evt.getDialog().getApplicationData();
					if (cs != null) 
					{
						Session sess = SessionManager.findCreateSession(cs.jabberLocal.getDomain(), cs.jabberRemote);
						if (sess != null) 
						{
							sess.sendBye(cs);
						}
					}
					
					Response res = SipService.messageFactory.createResponse(Response.OK, req);
					if (evt.getServerTransaction() == null)
					{
						ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
						tx.sendResponse(res);
					}
					else
					{
						evt.getServerTransaction().sendResponse(res);
					}
					return;
				}
			}			

			else if (req.getMethod().equals(Request.CANCEL))
			{
				if (evt.getDialog() != null)
				{
					logger.info("[[SIP]] Got in dialog cancel");
					Response res = SipService.messageFactory.createResponse(Response.OK, req);
					if (evt.getServerTransaction() == null)
					{
						ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
						tx.sendResponse(res);
					}
					else
					{
						evt.getServerTransaction().sendResponse(res);
					}

					CallSession cs = (CallSession) evt.getDialog().getApplicationData();
					if (cs != null) 
					{
						Session sess = SessionManager.findCreateSession(cs.jabberLocal.getDomain(), cs.jabberRemote);
						if (sess != null) 
						{
							SipService.sendReject(cs);
							sess.sendBye(cs);
						}
					}
					
					return;
				}
			}			

			else if (req.getMethod().equals(Request.ACK))
			{
				return;
			}
			else if (req.getMethod().equals(Request.OPTIONS))
			{
				
				int	resp = Response.OK;
				
				if (optionsmode) {
					
					
					if (evt.getDialog() != null)
					{
								
						logger.info("[[SIP]] Got in dialog OPTIONS");
						resp = Response.OK;
							
							// temp: debug message to validate this OPTIONS scenario
							CallSession cs = (CallSession) evt.getDialog().getApplicationData();
							if (cs == null) 
							{ 
								logger.error("[[SIP]] OPTIONS CallSession is null?");	
							} 
						
					} else {
						
						logger.info("[[SIP]] Rejecting out-of-dialog OPTIONS");
						resp = Response.CALL_OR_TRANSACTION_DOES_NOT_EXIST;
					}
				}
				
				try
				{
					DatagramSocket ds = new DatagramSocket();
					ds.close();
				}
				catch (SocketException e)
				{
					logger.error("[[SIP]] No more sockets available", e);
					resp = Response.SERVER_INTERNAL_ERROR;
				}
				Response res = SipService.messageFactory.createResponse(resp, req);
				SipService.sipProvider.sendResponse(res);
				return;
			}
			// SIP UPDATE (dumbstart, purposed as Jingle session-info counterpart)
			else if (req.getMethod().equals(Request.UPDATE))
			{
				
				int	resp = Response.OK;
				
				if (optionsmode) {
					
					
					if (evt.getDialog() != null)
					{
								
						logger.info("[[SIP]] Got UPDATE request");
						resp = Response.OK;
							
						// temp: debug message to validate this OPTIONS scenario
						CallSession cs = (CallSession) evt.getDialog().getApplicationData();
						if (cs == null) 
						{ 
							logger.error("[[SIP]] UPDATE CallSession is null?");	
						} 
						
						Header require = (Header)req.getHeader(Require.NAME);
						Header sessexp = (Header)req.getHeader("Session-Expires");
				        logger.debug("[[SIP]] SESSION-TIMER: "+require+":"+sessexp);
							
					} else {
						
						logger.info("[[SIP]] No Session - Rejecting UPDATE");
						resp = Response.CALL_OR_TRANSACTION_DOES_NOT_EXIST;
					}
				}
				
				try
				{
					DatagramSocket ds = new DatagramSocket();
					ds.close();
				}
				catch (SocketException e)
				{
					logger.error("[[SIP]] No more sockets available", e);
					resp = Response.SERVER_INTERNAL_ERROR;
				}
				Response res = SipService.messageFactory.createResponse(resp, req);
				SipService.sipProvider.sendResponse(res);
				return;
			}
			
			else if (req.getMethod().equals(Request.INFO))
			{
				CallSession cs = (CallSession) evt.getDialog().getApplicationData();
				if (cs != null && cs.vRelay != null)
				{
					cs.vRelay.sendFIR();
					Response res = SipService.messageFactory.createResponse(Response.OK, req);

					if (evt.getServerTransaction() == null)
					{
						ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
						tx.sendResponse(res);
					}
					else
					{
						evt.getServerTransaction().sendResponse(res);
					}					
				
					return;
				}
			}

			Response res = SipService.messageFactory.createResponse(Response.FORBIDDEN, req);
			if (evt.getServerTransaction() == null)
			{
				ServerTransaction tx = ((SipProvider) evt.getSource()).getNewServerTransaction(req);
				tx.sendResponse(res);
			}
			else
			{
				evt.getServerTransaction().sendResponse(res);
			}

			logger.error("[[SIP]] Rejecting request");
		} 
		catch (ParseException e)
		{
			logger.error("[[SIP]] Error processing sip Request!\n" + req.toString(), e);
		} 
		catch (TransactionAlreadyExistsException e)
		{
			logger.error("[[SIP]] Error processing sip Request!\n" + req.toString(), e);
		} 
		catch (TransactionUnavailableException e)
		{
			logger.error("[[SIP]] Error processing sip Request!\n" + req.toString(), e);
		} 
		catch (SipException e)
		{
			logger.error("[[SIP]] Error processing sip Request!\n" + req.toString(), e);
		} 
		catch (InvalidArgumentException e)
		{
			logger.error("[[SIP]] Error processing sip Request!\n" + req.toString(), e);
		} 
		catch(Exception e)
		{
			logger.error("[[SIP]] Error processing sip Request!\n" + req.toString(), e);
		}
	}

	public void processResponse(ResponseEvent evt)
	{
		Response resp = evt.getResponse();
		String method = ((CSeqHeader) resp.getHeader(CSeqHeader.NAME)).getMethod();
		int status = resp.getStatusCode();
		logger.info("[[SIP]] Got a response to " + method);
		
		try
		{
			if (method.equals(Request.SUBSCRIBE))
			{
				if (subscribeEmu) {
					
					// force emulation regardless of reply
					status = 500;
				}
				
				if (status >= 200 && status < 300)
				{
					logger.info("[[SIP]] 200 OK to SUBSCRIBE, updating route info");
					String callid = ((CallIdHeader) resp.getHeader(CallIdHeader.NAME)).getCallId();
					FromHeader fh = (FromHeader) resp.getHeader("From");
					String user = ((SipURI) fh.getAddress().getURI()).getUser();
					SipSubscription sub = SipSubscriptionManager.getSubscriptionByCallID(user, callid);

					// Subscription can be null if it's a response to Subscribe / Expires 0
					if (sub != null)
					{
						sub.updateSubscription(resp);
					}
				}
				else if (status >= 400)
				{
					logger.info("[[SIP]] Subscribe failed");
					FromHeader fh = (FromHeader) resp.getHeader("From");
					String dest = ((SipURI) fh.getAddress().getURI()).getUser();	

					ToHeader th = (ToHeader) resp.getHeader("To");
					String src = ((SipURI) th.getAddress().getURI()).getUser();	
					String callid = ((CallIdHeader) resp.getHeader(CallIdHeader.NAME)).getCallId();

					if (status != 404)
					{
						logger.info("[[SIP]] emulating presence");
						JID destination = UriMappings.toJID(dest);
						Session sess = SessionManager.findCreateSession(host, destination);

						sess.sendSubscribeRequest(new JID(src + "@" + host), destination, "subscribed");			
						sess.sendPresence(Presence.buildOnlinePresence(src, dest, host));
					}
					@SuppressWarnings("unused")
					SipSubscription sub = SipSubscriptionManager.removeSubscriptionByCallID(dest, callid);
				}
			}
			else if (method.equals(Request.INVITE))
			{
				if (status >= 200 && status < 300)
				{
					Dialog d = evt.getDialog();
					if (d == null) 
					{
						logger.error("[[SIP]] Dialog is null");
						return;
					}
					
					CallSession cs = (CallSession) d.getApplicationData();
					if (cs == null) 
					{
						logger.error("[[SIP]] CallSession is null");

						ClientTransaction ct = evt.getClientTransaction();
						if (ct == null) 
						{
							logger.error("[[SIP]] Client transaction null!!!!");
							return;
						}
						else if (ct.getApplicationData() == null) 
						{
							logger.error("[[SIP]] Client transaction application data null!!!!");
							return;
						}

						logger.debug("[[SIP]] Found CallSession in transaction, re-pairing");
						d.setApplicationData(ct.getApplicationData());
						cs = (CallSession) ct.getApplicationData();
						cs.sipDialog = d;
					}
					
					d.sendAck(d.createAck(d.getLocalSeqNumber()));
					
					FromHeader fh = (FromHeader) resp.getHeader("From");
					String dest = ((SipURI) fh.getAddress().getURI()).getUser();		

					JID destination = UriMappings.toJID(dest);
					Session sess = SessionManager.findCreateSession(host, destination);
					
					if(!cs.callAccepted)
			                {
                			        // RFC3261 says that all 200 OK to an invite get passed to UAC, even re-trans, so we need to filter
                        			cs.parseSDP(new String(resp.getRawContent()), false);
                        			sess.sendAccept(cs);
                        			cs.callAccepted = true;
                    			}
				}
				else if (status >= 400)
				{
					logger.info("[[SIP]] Invite failed, ending call");

					Dialog d = evt.getDialog();
					if (d == null) 
					{
						logger.error("[[SIP]] Dialog is null");
						return;
					}

					CallSession cs = (CallSession) d.getApplicationData();
					// terminate the jabber side if it hasn't been done already
					if (cs != null && CallManager.getSession(cs.jabberSessionId) != null)
					{
						FromHeader fh = (FromHeader) resp.getHeader("From");
						String dest = ((SipURI) fh.getAddress().getURI()).getUser();	

						JID destination = UriMappings.toJID(dest);
						Session sess = SessionManager.findCreateSession(host, destination);

						sess.sendBye(cs);
					}
				}
			}
			else if (method.equals(Request.NOTIFY))
			{
				if (status == 418)
				{
					logger.info("[[SIP]] Subcription is no longer known, removing");
					FromHeader fh = (FromHeader) resp.getHeader("From");
					String dest = ((SipURI) fh.getAddress().getURI()).getUser();		
					
					String callid = ((CallIdHeader) resp.getHeader(CallIdHeader.NAME)).getCallId();
					
					SipSubscription sub = SipSubscriptionManager.getWatcherByCallID(dest, callid);
					if (sub != null)
					{
						logger.debug("[[SIP]] Watcher removed ok");
						SipSubscriptionManager.removeWatcher(dest, sub);
					}
				}
			}
			// Very basic MESSAGE handling for replies
			else if (method.equals(Request.MESSAGE))
			{
				if (status >= 400) {
					logger.info("[[SIP]] MESSAGE failed with status "+status);
				}
				else if (status == 200) {
					logger.info("[[SIP]] MESSAGE delivered");
				}
			}
		}
		catch (Exception e)
		{
			logger.error("[[SIP]] Error processing sip Response!\n" + resp.toString(), e);
		}
	}

	public void processTimeout(TimeoutEvent evt)
	{

	}

	public void processTransactionTerminated(TransactionTerminatedEvent evt)
	{

	}

}
