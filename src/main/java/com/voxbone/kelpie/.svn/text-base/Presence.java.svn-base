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


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

import javax.sip.address.SipURI;
import javax.sip.header.FromHeader;
import javax.sip.header.ToHeader;
import javax.sip.message.Request;

import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.jabberstudio.jso.Packet;
import org.jabberstudio.jso.StreamElement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ContentHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.AttributesImpl;

/**
 * Generic representation of presence of an endpoint
 * can be generated from either a SIP NOTIFY or an XMPP status message
 *
 */
public class Presence
{

	// XML documents types
	@SuppressWarnings("unused")
	private static final String PIDF_XML           = "pidf+xml";

	// pidf elements and attributes
	private static final String PRESENCE_ELEMENT   = "presence";
	@SuppressWarnings("unused")
	private static final String NS_ELEMENT         = "xmlns";
	private static final String NS_VALUE           = "urn:ietf:params:xml:ns:pidf";
	private static final String ENTITY_ATTRIBUTE   = "entity";
	private static final String TUPLE_ELEMENT      = "tuple";
	private static final String ID_ATTRIBUTE       = "id";
	private static final String STATUS_ELEMENT     = "status";
	@SuppressWarnings("unused")
	private static final String ONLINE_STATUS      = "open";
	@SuppressWarnings("unused")
	private static final String OFFLINE_STATUS     = "closed";
	private static final String BASIC_ELEMENT      = "basic";
	@SuppressWarnings("unused")
	private static final String CONTACT_ELEMENT    = "contact";
	private static final String NOTE_ELEMENT       = "note";
	@SuppressWarnings("unused")
	private static final String PRIORITY_ATTRIBUTE = "priority";

	// rpid elements and attributes
	@SuppressWarnings("unused")
	private static final String RPID_NS_ELEMENT    = "xmlns:rpid";
	private static final String RPID_NS_VALUE      = "urn:ietf:params:xml:ns:pidf:rpid";
	@SuppressWarnings("unused")
	private static final String DM_NS_ELEMENT      = "xmlns:dm";
	private static final String DM_NS_VALUE        = "urn:ietf:params:xml:ns:pidf:data-model";
	private static final String PERSON_ELEMENT     = "person";
	@SuppressWarnings("unused")
	private static final String NS_PERSON_ELT      = "dm:person";
	private static final String ACTIVITY_ELEMENT   = "activities";
	@SuppressWarnings("unused")
	private static final String NS_ACTIVITY_ELT    = "rpid:activities";
	private static final String AWAY_ELEMENT       = "away";
	@SuppressWarnings("unused")
	private static final String NS_AWAY_ELT        = "rpid:away";
	private static final String BUSY_ELEMENT       = "busy";
	@SuppressWarnings("unused")
	private static final String NS_BUSY_ELT        = "rpid:busy";
	private static final String OTP_ELEMENT        = "on-the-phone";
	@SuppressWarnings("unused")
	private static final String NS_OTP_ELT         = "rpid:on-the-phone";

	// namespace wildcard
	private static final String ANY_NS             = "*";


	String resource;
	String from;
	String to;
	String type;  // sip: "open" "closed", jabber: null, "unavailable"
	String show;
	String note;


	static Logger logger = Logger.getLogger(Presence.class);

	
	private static String statusNoteOnline;
	private static String statusNoteUnknown;

	public static void configure(Properties properties)
	{
		statusNoteOnline = properties.getProperty("com.voxbone.kelpie.status_note.online", "Kelpie Phone");
		statusNoteUnknown = properties.getProperty("com.voxbone.kelpie.status_note.unknown", "Unknown");
	}


	private Presence()
	{
		this.resource = null;
		this.from = null;
		this.to = null;
		this.type = null;  // sip: "open" "closed", jabber: null, "unavailable"
		this.show = null;
		this.note = null;
	}

	public Presence(Request req) throws UnsupportedEncodingException, SAXException, IOException
	{
		ToHeader th = (ToHeader) req.getHeader("To");
		FromHeader fh = (FromHeader) req.getHeader("From");

		from = ((SipURI) fh.getAddress().getURI()).getUser();
		to = ((SipURI) th.getAddress().getURI()).getUser();

		byte [] body = req.getRawContent();

		parsePidf(body);
	}

	public Presence(Packet p)
	{
		if (p.getTo() != null)
		{
			p.getTo().getNode();
		}
		this.from = UriMappings.toSipId(p.getFrom());

		this.resource = p.getFrom().getResource();

		if (p.getAttributeValue("type") != null && p.getAttributeValue("type").equals("unavailable"))
		{
			this.type = "closed";
		}
		else
		{
			this.type = "open";
		}

		StreamElement se = p.getFirstElement("show");
		if (se != null)
		{
			this.show = se.normalizeText();
		}

		se = p.getFirstElement("status");
		if (se != null)
		{
			this.note = se.normalizeText();
		}
	}

	private void parsePidf(byte [] body) throws SAXException, IOException, UnsupportedEncodingException
	{
		DOMParser parser = new DOMParser();
		if (body.length > 0)
		{
			try
			{
				parser.parse(new InputSource(new StringReader(new String(body, 0, body.length, "UTF8"))));
			}
			catch (SAXException e)
			{
				logger.error("parsing of presence pidf failed : ", e);
				logger.debug("SAXException -> body contents : " + new String(body, "UTF8"));
				throw e;
			}
			Document doc = parser.getDocument();

			NodeList presList = doc.getElementsByTagNameNS(NS_VALUE, PRESENCE_ELEMENT);

			Node presNode = presList.item(0);

			Element presence = (Element) presNode;

			// RPID area

			// due to a lot of changes in the past years to this functionality,
			// the namespace used by servers and clients are often wrong so we just
			// ignore namespaces here

			NodeList personList = presence.getElementsByTagNameNS(ANY_NS, PERSON_ELEMENT);

			Node personNode = personList.item(0);
			Element person = (Element) personNode;

			if (person != null)
			{
				NodeList activityList = person.getElementsByTagNameNS(ANY_NS, ACTIVITY_ELEMENT);

				if (activityList.getLength() > 0)
				{
					Element activity = null;

					// find the first correct activity
					for (int i = 0; i < activityList.getLength(); i++)
					{
						Node activityNode = activityList.item(i);

						if (activityNode.getNodeType() != Node.ELEMENT_NODE)
						{
							continue;
						}

						activity = (Element) activityNode;
						NodeList statusList = activity.getChildNodes();
						for (int j = 0; j < statusList.getLength(); j++)
						{
							Node statusNode = statusList.item(j);
							if (statusNode.getNodeType() == Node.ELEMENT_NODE)
							{
								String statusname = statusNode.getLocalName();
								if (statusname.equals(AWAY_ELEMENT))
								{
									show = "away";
									break;
								}
								else if (statusname.equals(BUSY_ELEMENT))
								{
									show = "dnd";
									break;
								}
								else if (statusname.equals(OTP_ELEMENT))
								{
									show = "dnd";
									break;
								}
							}
						}

						if (show != null)
						{
							break;
						}
					}
				}
			}

			NodeList tupleList = presence.getElementsByTagNameNS(ANY_NS, TUPLE_ELEMENT);

			Node tupleNode = tupleList.item(0);

			Element tuple = (Element) tupleNode;
			this.resource = tuple.getAttribute("id");
			NodeList statuses = tuple.getElementsByTagNameNS(ANY_NS, STATUS_ELEMENT);

			Element statusElement = (Element) statuses.item(0);
			NodeList basicList = statusElement.getElementsByTagNameNS(ANY_NS, BASIC_ELEMENT);

			Element basic = (Element) basicList.item(0);
			if (basic != null)
			{
				Node node = basic.getFirstChild();
				if (node != null)
				{
					this.type = node.getNodeValue();
				}
			}

			NodeList nodeList = tuple.getElementsByTagNameNS(ANY_NS, NOTE_ELEMENT);

			if (nodeList.getLength() > 0 && nodeList.item(0).getFirstChild() != null)
			{
				this.note = nodeList.item(0).getFirstChild().getNodeValue();
			}
		}
	}
	
	byte [] buildPidf(String domain)
	{
		OutputFormat of = new OutputFormat("XML", "UTF-8", true);
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		of.setIndent(1);
		of.setIndenting(true);

		XMLSerializer serializer = new XMLSerializer(os, of);

		try
		{
			ContentHandler hd = serializer.asContentHandler();
			hd.startPrefixMapping("", NS_VALUE);
			hd.startPrefixMapping("rpid", RPID_NS_VALUE);
			hd.startPrefixMapping("dm", DM_NS_VALUE);

			hd.startDocument();

			AttributesImpl atts = new AttributesImpl();
			atts.addAttribute(NS_VALUE, ENTITY_ATTRIBUTE, "", "", "pres:" + this.from + "@" + domain);
			hd.startElement(NS_VALUE, PRESENCE_ELEMENT, "", atts);

			atts.clear();
			atts.addAttribute(NS_VALUE, ID_ATTRIBUTE, "", "", this.resource);
			hd.startElement(NS_VALUE, TUPLE_ELEMENT, "", atts);

			atts.clear();
			hd.startElement(NS_VALUE, STATUS_ELEMENT, "", atts);
			hd.startElement(NS_VALUE, BASIC_ELEMENT, "", atts);
			hd.characters(this.type.toCharArray(), 0, this.type.toCharArray().length);
			hd.endElement(NS_VALUE, BASIC_ELEMENT, "");
			hd.endElement(NS_VALUE, STATUS_ELEMENT, "");

			if (this.note != null)
			{
				hd.startElement(NS_VALUE, NOTE_ELEMENT, "", atts);
				hd.characters(this.note.toCharArray(), 0, this.note.toCharArray().length);
				hd.endElement(NS_VALUE, NOTE_ELEMENT, "");
			}

			hd.endElement(NS_VALUE, TUPLE_ELEMENT, "");

			atts.addAttribute(DM_NS_VALUE, ID_ATTRIBUTE, "", "", this.resource);
			hd.startElement(DM_NS_VALUE, PERSON_ELEMENT, "", atts);
			atts.clear();

			hd.startElement(RPID_NS_VALUE, ACTIVITY_ELEMENT, "", atts);

			if (this.show != null)
			{
				if (this.show.equals("away"))
				{
					hd.startElement(RPID_NS_VALUE, AWAY_ELEMENT, "", atts);
					hd.endElement(RPID_NS_VALUE, AWAY_ELEMENT, "");
				}
				else if (this.show.equals("dnd") || this.show.equals("xa"))
				{
					hd.startElement(RPID_NS_VALUE, BUSY_ELEMENT, "", atts);
					hd.endElement(RPID_NS_VALUE, BUSY_ELEMENT, "");					 
				}
			}
			hd.endElement(RPID_NS_VALUE, ACTIVITY_ELEMENT, "");
			hd.endElement(DM_NS_VALUE, PERSON_ELEMENT, "");

			hd.endElement(NS_VALUE, PRESENCE_ELEMENT, "");

			hd.endDocument();

			os.close();
			return os.toByteArray();
		} 
		catch (IOException e)
		{
			logger.error("Error building presence document", e);
		} 
		catch (SAXException e)
		{
			logger.error("Error building presence document", e);
		}

		return null;
	}

	public static Presence buildOnlinePresence(String user, String dest, String domain)
	{
		String pidf = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		            + "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\""
		            +          " xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\""
		            +          " xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\""
		            +          " entity=\"pres:" + user + "@" + domain + "\">"
		            +   "<tuple id=\"KelpiePhone\">"
		            +     "<status>"
		            +       "<basic>open</basic>"
		            +     "</status>"
		            +     "<contact>sip:" + user + "@" + domain + "</contact>"
		            +     "<note>" + statusNoteOnline + "</note>"
		            +   "</tuple>"
		            + "</presence>";

		Presence p = new Presence();
		p.from = user;
		p.to = dest;
		try
		{
			p.parsePidf(pidf.getBytes());
		} 
		catch (UnsupportedEncodingException e)
		{
			logger.error("Error building presence document", e);
		} 
		catch (SAXException e)
		{
			logger.error("Error building presence document", e);
		} 
		catch (IOException e)
		{
			logger.error("Error building presence document", e);
		}
		
		return p;
	}
	
	public static Presence buildOfflinePresence(String user, String dest)
	{
		Presence p = new Presence();
		p.from = user;
		p.to = dest;
		p.type = "closed";
		
		return p;
	}

	public static Presence buildUnknownPresence(String user, String dest, String domain)
	{
		String pidf = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		            + "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\""
		            +          " xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\""
		            +          " xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\""
		            +          " entity=\"pres:" + user + "@" + domain + "\">"
		            +   "<tuple id=\"KelpiePhone\">"
		            +     "<status>"
		            +       "<basic>open</basic>"
		            +     "</status>"
		            +     "<contact>sip:" + user + "@" + domain + "</contact>"
		            +     "<note>" + statusNoteUnknown + "</note>"
		            +   "</tuple>"
		            + "</presence>";

		Presence p = new Presence();
		p.from = user;
		p.to = dest;
		try
		{
			p.parsePidf(pidf.getBytes());
		} 
		catch (UnsupportedEncodingException e)
		{
			logger.error("Error building presence document", e);
		} 
		catch (SAXException e)
		{
			logger.error("Error building presence document", e);
		} 
		catch (IOException e)
		{
			logger.error("Error building presence document", e);
		}
		
		return p;
	}

}
