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
import java.util.Date;
import java.util.LinkedList;
import java.util.Vector;

import javax.sdp.Attribute;
import javax.sdp.MediaDescription;
import javax.sdp.SdpException;
import javax.sdp.SdpFactory;
import javax.sdp.SdpParseException;
import javax.sdp.SessionDescription;
import javax.sdp.Time;
import javax.sip.ClientTransaction;
import javax.sip.Dialog;
import javax.sip.ServerTransaction;
import javax.sip.message.Message;

import org.apache.log4j.Logger;
import org.jabberstudio.jso.JID;
import org.jabberstudio.jso.NSI;
import org.jabberstudio.jso.Packet;
import org.jabberstudio.jso.StreamElement;


/**
 * 
 * Represents a call, contains the information for the Jingle as well as the sip side of the call
 *
 */
public class CallSession
{
	
	private static LinkedList<Payload> supported = new LinkedList<Payload>();

	public static Payload PAYLOAD_SPEEX = new Payload(99, "speex", 16000, 22000);
	public static Payload PAYLOAD_SPEEX2 = new Payload(98, "speex", 8000, 11000);
	public static Payload PAYLOAD_PCMU = new Payload(0, "PCMU", 8000, 64000);
	public static Payload PAYLOAD_PCMA = new Payload(8, "PCMA", 8000, 64000);
	public static Payload PAYLOAD_G723 = new Payload(4, "G723", 8000, 6300);
	public static VPayload PAYLOAD_H263 = new VPayload(34, "H263", 90000, 512000, 320, 200, 15);
	public static VPayload PAYLOAD_H264 = new VPayload(97, "H264", 90000, 512000, 640, 480, 15);
	public static VPayload PAYLOAD_H264SVC = new VPayload(96, "H264-SVC", 90000, 512000, 640, 480, 15);
	
	
	static
	{
		supported.add(PAYLOAD_SPEEX);
		supported.add(PAYLOAD_SPEEX2);
		supported.add(PAYLOAD_PCMU);
		supported.add(PAYLOAD_PCMA);		
		supported.add(PAYLOAD_G723);
		supported.add(PAYLOAD_H264);
		supported.add(PAYLOAD_H263);
		supported.add(PAYLOAD_H264SVC);
	}
	
	public static class Payload
	{
		int id;
		String name;
		int clockRate;
		int bitRate;
		
		public Payload(int id, String name, int clockRate, int bitRate)
		{
			this.id = id;
			this.name = name;
			this.clockRate = clockRate;
			this.bitRate = bitRate;
		}
	}
	
	public static class VPayload extends Payload
	{
		int width;
		int height;
		int framerate;
		
		public VPayload(int id, String name, int clockRate, int bitRate, int width, int height, int framerate)
		{
			super(id, name, clockRate, bitRate);
			this.width = width;
			this.height = height;
			this.framerate = framerate;
		}
	}
	
	String jabberSessionId;
	JID jabberRemote;
	JID jabberLocal;
	String jabberInitiator;
	String candidateUser;
	String candidateVUser;
	
	boolean sentTransport = false;
	boolean sentVTransport = false;
	boolean callAccepted = false;

	Dialog sipDialog;
	ServerTransaction inviteTransaction;
	ClientTransaction inviteOutTransaction;
	
	public RtpRelay relay;
	public RtpRelay vRelay;
	

	LinkedList<Payload> offerPayloads = new LinkedList<Payload>();
	LinkedList<Payload> answerPayloads = new LinkedList<Payload>();
	
	LinkedList<VPayload> offerVPayloads = new LinkedList<VPayload>();
	LinkedList<VPayload> answerVPayloads = new LinkedList<VPayload>();
	

	Logger logger = Logger.getLogger(this.getClass());
	
	private static int nextInternalCallId = 0;
	public String internalCallId;


	public CallSession()
	{
		internalCallId = "CS" + String.format("%08x", nextInternalCallId++);
		try
		{
			relay = new RtpRelay(this, false);
		} 
		catch (IOException e)
		{
			logger.error("Can't setup rtp relay", e);
		}
	}
	
	private boolean isSupportedPayload(Payload payload)
	{
		for (Payload p : supported)
		{
			if (p.name.equalsIgnoreCase(payload.name) && payload.clockRate == p.clockRate)
			{
				return true;
			}
		}
		return false;
	}
	
	public Payload getByName(String name, int clockRate)
	{
		for (Payload p : supported)
		{
			if (p.name.equalsIgnoreCase(name) && p.clockRate == clockRate)
			{
				return p;
			}
		}
		return null;
	}
	
	public Payload getByName(String name)
	{
		for (Payload p : supported)
		{
			if (p instanceof VPayload)
			{
				VPayload vp = (VPayload) p;
				if (p.name.equalsIgnoreCase(name))
				{
					return vp;
				}
			}
		}
		return null;
	}
	
	public Payload getById(int id)
	{
		for (Payload p : supported)
		{
			if (p.id == id)
			{
				return p;
			}
		}
		return null;		
	}
	
	public void parseInitiate(Packet p)
	{
		StreamElement session = p.getFirstElement(new NSI("session", "http://www.google.com/session"));
		
		jabberSessionId = session.getID();
		jabberRemote = p.getFrom();
		jabberLocal = p.getTo();
		jabberInitiator = session.getAttributeValue("initiator");	
		
		parseSession(session, true);
	}
	
	public void parseAccept(Packet p)
	{
		StreamElement session = p.getFirstElement();
		parseSession(session, false);
	}

	private void parseSession(StreamElement session, boolean offer)
	{
		StreamElement description = session.getFirstElement("description");
		
		if (description.getNamespaceURI().equals("http://www.google.com/session/video"))
		{
			logger.info("[[" + internalCallId + "]] Video call detected, enabling video rtp stream");
			if (vRelay == null)
			{
				try
				{
					vRelay = new RtpRelay(this, true);
				} 
				catch (IOException e)
				{
					logger.error("Can't setup video rtp relay", e);
				}
			}
		}
		for (Object opt : description.listElements())
		{
			StreamElement pt = (StreamElement) opt;
			
			if (pt.getNamespaceURI().equals("http://www.google.com/session/video") && pt.getLocalName().equals("payload-type"))
			{
				try
				{
					int id = Integer.parseInt(pt.getAttributeValue("id"));
					String name = pt.getAttributeValue("name");
	
					// int width = Integer.parseInt(pt.getAttributeValue("width"));
					// int height = Integer.parseInt(pt.getAttributeValue("height"));
					//int framerate = Integer.parseInt(pt.getAttributeValue("framerate"));
					
					Payload p = getByName(name);
					if (p != null && p instanceof VPayload)
					{
						VPayload tmp = (VPayload) p;
						// save the rtp map id, but load in our offical config....
						VPayload vp = new VPayload(id, tmp.name, tmp.clockRate, tmp.bitRate, tmp.width, tmp.height, tmp.framerate);
						
						if (offer)
						{
							offerVPayloads.add(vp);
						}
						else
						{
							answerVPayloads.add(vp);
						}
					}
				}
				catch (NumberFormatException e) 
				{
					// ignore tags we don't understand (but write full log, in case we need to investigate)
					logger.warn("[[" + internalCallId + "]] failed to parse tag in session : ", e);
					logger.debug("[[" + internalCallId + "]] NumberFormatException -> session contents : " + session.toString());
					logger.debug("[[" + internalCallId + "]] NumberFormatException -> description item contents : " + pt.toString());
				}
			}
			else if(pt.getNamespaceURI().equals("http://www.google.com/session/phone") && pt.getLocalName().equals("payload-type"))
			{
				try
				{
					int id = Integer.parseInt(pt.getAttributeValue("id"));
					String name = pt.getAttributeValue("name");
					
					int clockrate = 0;
					if (pt.getAttributeValue("clockrate") != null) {
						clockrate = Integer.parseInt(pt.getAttributeValue("clockrate"));
					}
	
					int bitrate = 0;
					if (pt.getAttributeValue("bitrate") != null)
					{
						bitrate = Integer.parseInt(pt.getAttributeValue("bitrate"));
					}
	
					Payload payload = new Payload(id, name, clockrate, bitrate);
	
					if (isSupportedPayload(payload))
					{
						if (offer)
						{
							offerPayloads.add(payload);
						}
						else
						{
							answerPayloads.add(payload);
						}
					}
				}
				catch (NumberFormatException e) 
				{
					// ignore tags we don't understand (but write full log, in case we need to investigate)
					logger.warn("[[" + internalCallId + "]] failed to parse tag in session : ", e);
					logger.debug("[[" + internalCallId + "]] NumberFormatException -> session contents : " + session.toString());
					logger.debug("[[" + internalCallId + "]] NumberFormatException -> description item contents : " + pt.toString());
				}
			}
		}
	}
	
	public SessionDescription buildSDP(boolean offer)
	{
		SdpFactory sdpFactory = SdpFactory.getInstance();
		try
		{
			SessionDescription sd = sdpFactory.createSessionDescription();
			sd.setVersion(sdpFactory.createVersion(0));
			long ntpts = SdpFactory.getNtpTime(new Date());
			sd.setOrigin(sdpFactory.createOrigin("JabberGW", ntpts, ntpts, "IN", "IP4", SipService.getLocalIP()));

			sd.setSessionName(sdpFactory.createSessionName("Jabber Call"));
			Vector<Time> times = new Vector<Time>();
			times.add(sdpFactory.createTime());
			sd.setTimeDescriptions(times);
			sd.setConnection(sdpFactory.createConnection(SipService.getLocalIP()));
			
			int [] formats;
			
			Vector<Attribute> attributes = new Vector<Attribute>();
			
			if (offer)
			{
				formats = new int[offerPayloads.size() + 1];
				int i = 0;
				for (Payload p : offerPayloads)
				{
					formats[i++] = p.id;
					attributes.add(sdpFactory.createAttribute("rtpmap", Integer.toString(p.id) + " " + p.name + "/" + p.clockRate));
				}
			}
			else
			{
				formats = new int[answerPayloads.size() + 1];
				int i = 0;
				for (Payload p : answerPayloads)
				{
					formats[i++] = p.id;
					attributes.add(sdpFactory.createAttribute("rtpmap", Integer.toString(p.id) + " " + p.name + "/" + p.clockRate));
				}				
			}
			
			formats[formats.length - 1] = 101;
			
			attributes.add(sdpFactory.createAttribute("rtpmap", "101 telephone-event/8000"));
			attributes.add(sdpFactory.createAttribute("fmtp", "101 0-15"));
			
			MediaDescription md = sdpFactory.createMediaDescription("audio", this.relay.getSipPort(), 1, "RTP/AVP", formats);
			md.setAttributes(attributes);
			
			Vector<MediaDescription> mds = new Vector<MediaDescription>();
			mds.add(md);

			if (vRelay != null)
			{
				// video call, add video m-line
				attributes = new Vector<Attribute>();
				
				if (offer)
				{
					formats = new int[offerVPayloads.size()];
					int i = 0;
					for (Payload p : offerVPayloads)
					{
						formats[i++] = p.id;
						attributes.add(sdpFactory.createAttribute("rtpmap", Integer.toString(p.id) + " " + p.name + "/" + p.clockRate));						
						attributes.add(sdpFactory.createAttribute("fmtp", Integer.toString(p.id) + " packetization-rate=1"));
					}
				}
				else
				{
					formats = new int[answerVPayloads.size()];
					int i = 0;
					for (Payload p : answerVPayloads)
					{
						formats[i++] = p.id;
						attributes.add(sdpFactory.createAttribute("rtpmap", Integer.toString(p.id) + " " + p.name + "/" + p.clockRate));						
						attributes.add(sdpFactory.createAttribute("fmtp", Integer.toString(p.id) + " packetization-rate=1"));
					}				
				}
				
				attributes.add(sdpFactory.createAttribute("framerate", "30"));
				attributes.add(sdpFactory.createAttribute("rtcp", Integer.toString(this.vRelay.getSipRtcpPort())));

				md.setBandwidth("AS", 960);
				md = sdpFactory.createMediaDescription("video", this.vRelay.getSipPort(), 1, "RTP/AVP", formats);
				md.setAttributes(attributes);
				mds.add(md);
			}

			sd.setMediaDescriptions(mds);
			return sd;
		} 
		catch (SdpException e)
		{
			logger.error("Error building SDP", e);
		}
		return null;
	}
	
	public void parseSDP(String sdp, boolean offer)
	{
		SdpFactory sdpFactory = SdpFactory.getInstance();
		
		try
		{
			SessionDescription sd = sdpFactory.createSessionDescription(sdp);
			@SuppressWarnings("unchecked")
			Vector<MediaDescription> mdesc = (Vector<MediaDescription>) sd.getMediaDescriptions(false);

			for (MediaDescription md : mdesc)
			{			
				javax.sdp.Media media = md.getMedia();

				if (media.getMediaType().equals("video") && media.getMediaPort() != 0 )
				{
					logger.info("[[" + internalCallId + "]] Video sdp detected! starting video rtp stream...");
					
					if (vRelay == null)
					{
						try
						{
							vRelay = new RtpRelay(this, true);
						} 
						catch (IOException e)
						{
							logger.error("unable to create video relay!", e);
						}
					}

					int  remotePort = media.getMediaPort();
					String remoteParty = null;
					if (md.getConnection() != null)
					{
						remoteParty = md.getConnection().getAddress();
					}
					else
					{
						remoteParty = sd.getConnection().getAddress();
					}

					vRelay.setSipDest(remoteParty, remotePort);

					@SuppressWarnings("unchecked")
					Vector<Attribute> attributes = (Vector<Attribute>) md.getAttributes(false);
					for (Attribute attrib : attributes)
					{
						if (attrib.getName().equals("rtpmap"))
						{
							logger.debug("[[" + internalCallId + "]] Got attribute value " + attrib.getValue());
							String fields[] = attrib.getValue().split(" ", 2);
							int codec = Integer.parseInt(fields[0]);
							String name = fields[1].split("/")[0];
							int clockRate = Integer.parseInt(fields[1].split("/")[1]);
							logger.debug("[[" + internalCallId + "]] Payload " + codec + " rate " + clockRate + " is mapped to " + name);

							if (codec >= 96)
							{
								Payload bitRatePayload = getByName(name, clockRate);
								if (bitRatePayload != null && bitRatePayload instanceof VPayload)
								{
									VPayload tmp = (VPayload) bitRatePayload;
									VPayload p = new VPayload(codec, tmp.name, clockRate, tmp.bitRate, tmp.width, tmp.height, tmp.framerate);

									if (offer)
									{
										offerVPayloads.add(p);
									}
									else
									{
										answerVPayloads.add(p);
									}
								}						
							}
						}
					}
				}
				else
				{
					int remotePort = media.getMediaPort();
					String remoteParty = null;
					if (md.getConnection() != null)
					{
						remoteParty = md.getConnection().getAddress();
					}
					else
					{
						remoteParty = sd.getConnection().getAddress();
					}

					relay.setSipDest(remoteParty, remotePort);

					@SuppressWarnings("unchecked")
					Vector<String> codecs = (Vector<String>) media.getMediaFormats(false);
					for (String codec : codecs)
					{
						int id = Integer.parseInt(codec);
						logger.debug("[[" + internalCallId + "]] Got a codec " + id);
						if (id < 97)
						{
							Payload p = getById(id);
							if (p != null)
							{
								if (offer)
								{
									offerPayloads.add(p);
								}
								else
								{
									answerPayloads.add(p);
								}
							}
						}
					}

					@SuppressWarnings("unchecked")
					Vector<Attribute> attributes = (Vector<Attribute>) md.getAttributes(false);
					for (Attribute attrib : attributes)
					{
						if (attrib.getName().equals("rtpmap"))
						{
							logger.debug("[[" + internalCallId + "]] Got attribute value " + attrib.getValue());
							String fields[] = attrib.getValue().split(" ", 2);
							int codec = Integer.parseInt(fields[0]);
							String name = fields[1].split("/")[0];
							int clockRate = Integer.parseInt(fields[1].split("/")[1]);
							logger.debug("[[" + internalCallId + "]] Payload " + codec + " rate " + clockRate + " is mapped to " + name);

							if (codec >= 96)
							{
								Payload bitRatePayload = getByName(name, clockRate);
								if (bitRatePayload != null)
								{
									Payload p = new Payload(codec, name, clockRate, bitRatePayload.bitRate);
									if (offer)
									{
										offerPayloads.add(p);
									}
									else
									{
										answerPayloads.add(p);
									}
								}						
							}
						}
					}
				}
			}
		} 
		catch (SdpParseException e)
		{
			logger.error("Unable to parse SDP!", e);
		} 
		catch (SdpException e)
		{
			logger.error("Unable to parse SDP!", e);
		}		
	}

	public void parseInvite(Message message, Dialog d, ServerTransaction trans)
	{
		sipDialog = d;
		inviteTransaction = trans;
		parseSDP(new String(message.getRawContent()), true);
	}

}
