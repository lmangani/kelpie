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


import java.text.ParseException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.TooManyListenersException;

import javax.sip.ClientTransaction;
import javax.sip.Dialog;
import javax.sip.DialogState;
import javax.sip.InvalidArgumentException;
import javax.sip.ListeningPoint;
import javax.sip.ObjectInUseException;
import javax.sip.PeerUnavailableException;
import javax.sip.SipException;
import javax.sip.SipFactory;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.TransactionUnavailableException;
import javax.sip.TransportNotSupportedException;
import javax.sip.address.Address;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.ContactHeader;
import javax.sip.header.ContentTypeHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.HeaderFactory;
import javax.sip.header.MaxForwardsHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;
import javax.sip.message.Response;

import org.apache.log4j.Logger;

/**
 * Functions useful for building SIP messages
 *
 */
public class SipService
{

	public static AddressFactory addressFactory;
	public static HeaderFactory headerFactory;
	public static MessageFactory messageFactory;
	public static KelpieSipListener sipListener;
	public static SipProvider sipProvider;
	private SipStack sipStack;
	private SipFactory sipFactory;
	private static Logger logger = Logger.getLogger(SipService.class);
	private int localport;
	private static String localip;
	private static String remoteip;


	public SipService(Properties properties)
	{
		localip = properties.getProperty("com.voxbone.kelpie.ip");
		localport = Integer.parseInt(properties.getProperty("com.voxbone.kelpie.sip_port", "5060"));
		remoteip = properties.getProperty("com.voxbone.kelpie.sip_gateway");
		
		sipListener = new KelpieSipListener(properties.getProperty("com.voxbone.kelpie.hostname"));

		sipFactory = SipFactory.getInstance();
		sipFactory.setPathName("gov.nist");
		properties.setProperty("javax.sip.STACK_NAME", "KelpieStack");

		try 
		{
			sipStack = sipFactory.createSipStack(properties);
			headerFactory = sipFactory.createHeaderFactory();
			addressFactory = sipFactory.createAddressFactory();
			messageFactory = sipFactory.createMessageFactory();			
		} 
		catch (PeerUnavailableException e) 
		{
			logger.error(e, e);
		}
		
		try 
		{
			ListeningPoint udp = sipStack.createListeningPoint(localip, localport, "udp");
			sipProvider = sipStack.createSipProvider(udp);
			sipProvider.setAutomaticDialogSupportEnabled(false);
			sipProvider.addSipListener(sipListener);
		} 
		catch (TransportNotSupportedException e) 
		{
			logger.error(e, e);
		} 
		catch (InvalidArgumentException e) 
		{
			logger.error(e, e);
		}
		catch (ObjectInUseException e) 
		{
			logger.error(e, e);
		} 
		catch (TooManyListenersException e) 
		{
			logger.error(e, e);
		}
	}

	public static String getRemoteIP()
	{
		return remoteip;
	}
	
	public static String getLocalIP()
	{
		return localip;
	}
	
	public static boolean acceptCall(CallSession cs)
	{
		try
		{
			Request req = cs.inviteTransaction.getRequest();
			Response resp = messageFactory.createResponse(Response.OK, cs.inviteTransaction.getRequest());
			ContentTypeHeader cth = headerFactory.createContentTypeHeader("application", "sdp");
			Object sdp = cs.buildSDP(false);
			
			ToHeader th = (ToHeader) req.getHeader("To");
			String dest = ((SipURI) th.getAddress().getURI()).getUser();

			ListeningPoint lp = sipProvider.getListeningPoint(ListeningPoint.UDP);
			
			Address localAddress = addressFactory.createAddress("sip:" + dest + "@" + lp.getIPAddress() + ":" + lp.getPort());
			
			ContactHeader ch = headerFactory.createContactHeader(localAddress);
			resp.addHeader(ch);
			
			resp.setContent(sdp, cth);
			cs.inviteTransaction.sendResponse(resp);
		} 
		catch (ParseException e)
		{
			logger.error("Error accepting call", e);
			return false;
		} 
		catch (SipException e)
		{
			logger.error("Error accepting call", e);
			return false;
		} 
		catch (InvalidArgumentException e)
		{
			logger.error("Error accepting call", e);
			return false;
		}
		return true;
	}

	public static boolean sendBye(CallSession cs)
	{
		Request req;
		try
		{
			if (   cs.inviteOutTransaction != null
			    && (cs.sipDialog.getState() == null || cs.sipDialog.getState() == DialogState.EARLY))
			{
				req = cs.inviteOutTransaction.createCancel();
				ClientTransaction t = sipProvider.getNewClientTransaction(req);
				t.sendRequest();
				return false;
			}
			else
			{
				req = cs.sipDialog.createRequest(Request.BYE);
				ClientTransaction t = sipProvider.getNewClientTransaction(req);
				cs.sipDialog.sendRequest(t);
			}
		} 
		catch (SipException e)
		{
			logger.error("Error sending BYE", e);
		}
		
		return true;
	}

	public static boolean sendReject(CallSession cs)
	{
		try
		{
			Request req = cs.inviteTransaction.getRequest();
			Response resp = messageFactory.createResponse(Response.TEMPORARILY_UNAVAILABLE, cs.inviteTransaction.getRequest());
			
			ToHeader th = (ToHeader) req.getHeader("To");
			String dest = ((SipURI) th.getAddress().getURI()).getUser();

			ListeningPoint lp = sipProvider.getListeningPoint(ListeningPoint.UDP);
			
			Address localAddress = addressFactory.createAddress("sip:" + dest + "@" + lp.getIPAddress() + ":" + lp.getPort());
			
			ContactHeader ch = headerFactory.createContactHeader(localAddress);
			resp.addHeader(ch);
			
			cs.inviteTransaction.sendResponse(resp);
		} 
		catch (Exception e)
		{
			logger.error("Error sending Reject", e);
		}
		
		return true;
	}
	
	
	public static boolean sendDTMFinfo(CallSession cs, char dtmf)
	{
		Request req;
		try
		{
			ContentTypeHeader cth = headerFactory.createContentTypeHeader("application", "dtmf-relay");
			String body = 	"Signal=" + dtmf + "\r\nDuration=160";
			
			req = cs.sipDialog.createRequest(Request.INFO);
			ClientTransaction t = sipProvider.getNewClientTransaction(req);
			req.setContent(body, cth);
			cs.sipDialog.sendRequest(t);				
		} 
		catch (SipException e)
		{
			logger.error("Error sending FVR INFO", e);
		} 
		catch (ParseException e)
		{
			logger.error("Error sending FVR INFO", e);
		}
		
		return true;
	}
	
	public static boolean sendVideoUpdate(CallSession cs)
	{
		Request req;
		try
		{
			ContentTypeHeader cth = headerFactory.createContentTypeHeader("application", "media_control+xml");
			String body = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
			            + "<media_control>"
			            +   "<vc_primitive>"
			            +     "<to_encoder>"
			            +       "<picture_fast_update>"
			            +       "</picture_fast_update>"
			            +     "</to_encoder>"
			            +   "</vc_primitive>"
			            + "</media_control>";
			
			req = cs.sipDialog.createRequest(Request.INFO);
			ClientTransaction t = sipProvider.getNewClientTransaction(req);
			req.setContent(body, cth);
			cs.sipDialog.sendRequest(t);				
		} 
		catch (SipException e)
		{
			logger.error("Error sending FVR INFO", e);
		} 
		catch (ParseException e)
		{
			logger.error("Error sending FVR INFO", e);
		}
		
		return true;
	}
	
	public static boolean sendInvite(CallSession cs, String domain)
	{
		FromHeader fromHeader = null;
		ToHeader toHeader = null;
		URI requestURI = null;
		URI fromURI = null;

		try
		{
			requestURI = addressFactory.createURI("sip:" + cs.jabberLocal.getNode() + "@" + remoteip);
			toHeader = headerFactory.createToHeader(addressFactory.createAddress(requestURI), null);
			fromURI = addressFactory.createURI("sip:" + UriMappings.toSipId(cs.jabberRemote) + "@" + domain);
			fromHeader = headerFactory.createFromHeader(addressFactory.createAddress(fromURI), null);

			int tag = (int) (Math.random() * 100000);
			fromHeader.setTag(Integer.toString(tag));

			ArrayList<ViaHeader> viaHeaders = new ArrayList<ViaHeader>();
			ViaHeader viaHeader = null;

			ListeningPoint lp = sipProvider.getListeningPoint(ListeningPoint.UDP);

			viaHeader = headerFactory.createViaHeader(lp.getIPAddress(), lp.getPort(), lp.getTransport(), null);
			viaHeaders.add(viaHeader);

			CallIdHeader callIdHeader = sipProvider.getNewCallId();
			CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(1L, Request.INVITE);
			MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);
			ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");

			Request request = messageFactory.createRequest(requestURI, Request.INVITE, callIdHeader, cSeqHeader, fromHeader, toHeader, viaHeaders, maxForwards, contentTypeHeader, cs.buildSDP(true));

			Address localAddress = addressFactory.createAddress("sip:" + UriMappings.toSipId(cs.jabberRemote) + "@" + lp.getIPAddress() + ":" + lp.getPort());
			
			ContactHeader ch = headerFactory.createContactHeader(localAddress);
			request.addHeader(ch);

			ClientTransaction t = sipProvider.getNewClientTransaction(request);
			
			//t.setApplicationData(new ResponseInfo(listener, transaction));

			Dialog d = SipService.sipProvider.getNewDialog(t);
			cs.sipDialog = d;
			d.setApplicationData(cs);

			t.setApplicationData(cs);
			cs.inviteOutTransaction = t;
			t.sendRequest();
			
			return true;
		} 
		catch (ParseException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		} 
		catch (InvalidArgumentException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		} 
		catch (TransactionUnavailableException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		} 
		catch (SipException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		}
		
		return false;
	}
	
	public static boolean sendMessageMessage(MessageMessage mm, String domain)
	{
		FromHeader fromHeader = null;
		ToHeader toHeader = null;
		URI requestURI = null;
		URI fromURI = null;

		try
		{
			requestURI = addressFactory.createURI("sip:" + mm.to + "@" + remoteip);
			toHeader = headerFactory.createToHeader(addressFactory.createAddress(requestURI), null);
			fromURI = addressFactory.createURI("sip:" + mm.from + "@" + domain);
			fromHeader = headerFactory.createFromHeader(addressFactory.createAddress(fromURI), null);

			int tag = (int) (Math.random() * 100000);
			fromHeader.setTag(Integer.toString(tag));

			ArrayList<ViaHeader> viaHeaders = new ArrayList<ViaHeader>();
			ViaHeader viaHeader = null;

			ListeningPoint lp = sipProvider.getListeningPoint(ListeningPoint.UDP);

			viaHeader = headerFactory.createViaHeader(lp.getIPAddress(), lp.getPort(), lp.getTransport(), null);
			viaHeaders.add(viaHeader);

			CallIdHeader callIdHeader = sipProvider.getNewCallId();
			CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(1L, Request.MESSAGE);
			MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);
			ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("text", "plain");

			Request request = messageFactory.createRequest(requestURI, "MESSAGE", callIdHeader, cSeqHeader, fromHeader, toHeader, viaHeaders, maxForwards, contentTypeHeader, mm.body);

			ClientTransaction t = sipProvider.getNewClientTransaction(request);
			
			t.sendRequest();
			
			return true;
		} 
		catch (ParseException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		} 
		catch (InvalidArgumentException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		} 
		catch (TransactionUnavailableException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		} 
		catch (SipException e)
		{
			logger.error("Error on SIPTransmitter:deliverMessage", e);
		}
		
		return false;
	}
}
