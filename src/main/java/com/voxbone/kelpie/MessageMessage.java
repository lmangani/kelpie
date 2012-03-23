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


import java.io.UnsupportedEncodingException;

import javax.sip.address.SipURI;
import javax.sip.header.CallIdHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.SubjectHeader;
import javax.sip.message.Request;

import org.jabberstudio.jso.Packet;
import org.jabberstudio.jso.StreamElement;

/**
 * Represents an Instant Message, able to be built from either a SIP or XMPP message
 *
 */
public class MessageMessage
{
	public String body;
	public String subject;
	public String thread;
	
	public String to;
	public String from;
	

	public MessageMessage(Packet p)
	{
		StreamElement firstElement = p.getFirstElement("body");
		if (firstElement != null)
		{
			body = firstElement.normalizeText();
		}
		to = p.getTo().getNode();
		from = UriMappings.toSipId(p.getFrom());

		if (p.getFirstElement("thread") != null)
		{
			thread = p.getFirstElement("thread").normalizeText();
		}
		else
		{
			thread = null;
		}
		
		if (p.getFirstElement("subject") != null)
		{
			subject = p.getFirstElement("subject").normalizeText();
		}
		else
		{
			subject = null;
		}
	}
	
	public MessageMessage(Request request)
	{
		to = ((SipURI) request.getRequestURI()).getUser();

		FromHeader fh = (FromHeader) request.getHeader(FromHeader.NAME);
		from = ((SipURI) fh.getAddress().getURI()).getUser();

		thread = ((CallIdHeader) request.getHeader(CallIdHeader.NAME)).getCallId();

		if (request.getHeader(SubjectHeader.NAME) != null)
		{
			subject = ((SubjectHeader) request.getHeader(SubjectHeader.NAME)).getSubject();
		}
		else
		{
			subject = null;
		}

		byte [] bMsg = request.getRawContent();
		try
		{
			body = new String(bMsg, 0, bMsg.length, "UTF8");
		} 
		catch (UnsupportedEncodingException e)
		{
			// What can't be represented in UTF8? :-)
		}
	}
}
