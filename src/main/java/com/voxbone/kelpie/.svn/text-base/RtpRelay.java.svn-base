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
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.spi.SelectorProvider;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.log4j.Logger;
import org.jabberstudio.jso.Packet;

import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.attribute.SourceAddress;
import de.javawi.jstun.attribute.UnknownMessageAttributeException;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.header.MessageHeader;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.Address;
import de.javawi.jstun.util.UtilityException;

/**
 * This is the RTP Media relay thread, can be for video or audio.
 * For the xmpp side it also takes care of the STUN signaling
 *
 */

public class RtpRelay extends Thread
{
	
	Timer retransTimer = new Timer("Stun Retransmit Thread");
	
	private class StunTransmitter extends TimerTask
	{
		byte [] message;
		SocketAddress dest;
		DatagramChannel socket;
	
		public StunTransmitter(byte [] message, SocketAddress dest, DatagramChannel socket)
		{
			this.message = message;
			this.dest = dest;
			this.socket = socket;
		}

		public void run()
		{
			logger.debug("[[" + cs.internalCallId + "]] Running RtpRelay::StunTransmitter ... : " + dest + " -- " + socket.socket().getLocalPort());
			try
			{
				if (socket.isOpen()) 
				{
					socket.send(ByteBuffer.wrap(message), dest);
				}
			} 
			catch (IOException e)
			{
				logger.error("[[" + cs.internalCallId + "]] RtpRelay::StunTransmitter sending failed ==> " + dest + " -- " + socket.socket().getLocalPort());
			}
		}
		
		public boolean cancel() 
		{
			logger.debug("[[" + cs.internalCallId + "]] Cancelling RtpRelay::StunTransmitter ... : " + dest + " -- " + socket.socket().getLocalPort());
			return super.cancel();
		}
	}
	
	
	BlockingQueue<Character> dtmfQueue = new LinkedBlockingQueue<Character>();
	private boolean video = false;


	private class DtmfGenerator extends Thread
	{

		@Override
		public void run()
		{
			while (sipSocket.isOpen())
			{
				char dtmf;
				try
				{
					dtmf = dtmfQueue.take();

					if (dtmf == '\0')
					{
						logger.debug("[[" + cs.internalCallId + "]] End flag detected in dtmf thread");
						break;
					}
					
					long ts = 0;
					synchronized (sipSocket)
					{
						ts = jabberTimestamp;
					}
					DtmfEvent de = new DtmfEvent(dtmf, ts, jabberSSRC);
					
					logger.debug("[[" + cs.internalCallId + "]] Preparing to send dtmf " + dtmf);
					
					synchronized (sipSocket)
					{
						ByteBuffer buffer = ByteBuffer.wrap(de.startPacket());
						RtpUtil.setSequenceNumber(buffer.array(), ++jabberSequence);
						try
						{
							sipSocket.send(buffer, sipDest);
						} 
						catch (IOException e)
						{
							logger.error("Error sending dtmf start packet!", e);
						}
					}
					
					for (int i = 0; i < 5; i++)
					{
						Thread.sleep(20);
						synchronized (sipSocket)
						{
							ByteBuffer buffer = ByteBuffer.wrap(de.continuationPacket());
							RtpUtil.setSequenceNumber(buffer.array(), ++jabberSequence);
							try
							{
								sipSocket.send(buffer, sipDest);
							} 
							catch (IOException e)
							{
								logger.error("Error sending dtmf continuation packet!", e);
							}
						}
					}
					
					for (int i = 0; i < 3; i++)
					{
						synchronized (sipSocket)
						{
							ByteBuffer buffer = ByteBuffer.wrap(de.endPacket());
							RtpUtil.setSequenceNumber(buffer.array(), ++jabberSequence);
							try
							{
								sipSocket.send(buffer, sipDest);
							} 
							catch (IOException e)
							{
								logger.error("Error sending dtmf end packet!", e);
							}
						}
					}

					// Ensure at least 40 ms between dtmfs

					Thread.sleep(40);
				} 
				catch (InterruptedException e)
				{
					// do nothing
				}
			}
			
			logger.debug("[[" + cs.internalCallId + "]] DtmfGenerator shut down");
		}
	}

	public Hashtable<String, StunTransmitter> transmitters = new Hashtable<String, StunTransmitter>();
	
	private class ID
	{
		byte [] id;

		public ID(byte [] id)
		{
			this.id = id;
		}

		@Override
		public int hashCode()
		{
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(id);
			return result;
		}

		@Override
		public boolean equals(Object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (obj == null)
			{
				return false;
			}
			if (getClass() != obj.getClass())
			{
				return false;
			}
			final ID other = (ID) obj;
			if (!Arrays.equals(id, other.id))
			{
				return false;
			}
			return true;
		}

	}

	private Hashtable<ID, Packet> idTable = new Hashtable<ID, Packet>();

	private DatagramChannel jabberSocket;
	private DatagramChannel sipSocket;
	private DatagramChannel jabberSocketRtcp;
	private DatagramChannel sipSocketRtcp;
	
	private SocketAddress jabberDest;
	private SocketAddress jabberDestRtcp;
	private SocketAddress sipDest;
	private SocketAddress sipDestRtcp;

	
	byte [] sipSSRC = null;
	byte [] jabberSSRC = null;

	long jabberTimestamp = 0;
	short jabberSequence = 0;
	
	long lastVUpate = 0;
	int firSeq = 0;
		
	Logger logger = Logger.getLogger(this.getClass());
	public static final int RTP_MIN_PORT = 8000;
	public static final int RTP_MAX_PORT = 10000;
	
	private static int nextPort = RTP_MIN_PORT;
	private CallSession cs = null;
	
	private DatagramChannel makeDatagramChannel(boolean any) throws IOException
	{
		DatagramChannel socket = DatagramChannel.open();
		while (!socket.socket().isBound())
		{
			nextPort += 1;
			if (nextPort > RTP_MAX_PORT)
			{
				nextPort = RTP_MIN_PORT;
			}
			logger.debug("[[" + cs.internalCallId + "]] trying to bind to port: " + nextPort);
			
			try
			{
				if (!any)
				{
					socket.socket().bind(new InetSocketAddress(SipService.getLocalIP(), nextPort));
				}
				else
				{
					socket.socket().bind(new InetSocketAddress(nextPort));
				}
			} 
			catch (SocketException e)
			{
				logger.error("Unable to make RTP socket!", e);
			}
		}
		return socket;
	}
	
	public void sendBind(String user, String me, String destIp, int destPort, Packet packet, boolean rtcp)
	{
		MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingRequest);
		Username name = new Username(user + me);
		try
		{
			sendMH.generateTransactionID();
		} 
		catch (UtilityException e)
		{
			logger.error("Unable to make stun transaction id", e);
		}
		sendMH.addMessageAttribute(name);
		
		idTable.put(new ID(sendMH.getTransactionID()), packet);
		
		try
		{
			byte [] data = sendMH.getBytes();
			logger.debug("[[" + cs.internalCallId + "]] Sending: " + Arrays.toString(data));
			
			DatagramChannel socket = null;
			
			if (rtcp)
			{
				socket = jabberSocketRtcp;
			}
			else
			{
				socket = jabberSocket;
			}
			
			synchronized (transmitters)
			{
				if (jabberDest == null)
				{
					logger.debug("[[" + cs.internalCallId + "]] Sending Bind to: " + destIp + ":" + destPort);
					StunTransmitter st = new StunTransmitter(data, new InetSocketAddress(destIp, destPort), socket);
					String key = name.getUsername() + "_" + destIp + ":" + destPort;
					if (transmitters.containsKey(key)) 
					{
						transmitters.get(key).cancel();
						transmitters.remove(key);
					}
					transmitters.put(key, st);
					logger.debug("[[" + cs.internalCallId + "]] RtpRelay::StunTransmitter scheduled (fast) [" + jabberSocket.socket().getLocalPort() + "][" + sipSocket.socket().getLocalPort() + "] ==> " + st.socket.socket().getLocalPort());
					retransTimer.schedule(st, 50, 50);
				}
			}
		} 
		catch (UtilityException e)
		{
			logger.error("Error in stun bind!", e);
		} 
	}
	
	public RtpRelay(CallSession cs, boolean video) throws IOException
	{
		this.video = video;
		this.cs = cs;
		
		jabberSocket = makeDatagramChannel(true);
		jabberSocketRtcp = makeDatagramChannel(true);

		sipSocket = makeDatagramChannel(false);
		sipSocketRtcp = makeDatagramChannel(false);
		
		logger.info("[[" + cs.internalCallId + "]] RtpRelay created [" + jabberSocket.socket().getLocalPort() + "][" + sipSocket.socket().getLocalPort() + "]");
		
		if (!video)
		{
			(new DtmfGenerator()).start();
		}
		start();
	}
	
	protected void finalize() throws Throwable 
	{
		logger.info("[[" + cs.internalCallId + "]] RtpRelay destroyed [" + jabberSocket.socket().getLocalPort() + "][" + sipSocket.socket().getLocalPort() + "]");
		super.finalize(); // not necessary if extending Object.
	}

	private void processStun(SocketAddress src, byte [] origData, DatagramChannel socket)
	{
		try
		{
			MessageHeader receiveMH = MessageHeader.parseHeader(origData);
			if (receiveMH.getType() == MessageHeaderType.BindingErrorResponse)
			{
				return;
			}
			
			receiveMH.parseAttributes(origData);
		
			if (receiveMH.getType() == MessageHeaderType.BindingRequest)
			{
				MessageHeader sendMH = new MessageHeader(MessageHeaderType.BindingResponse);
				sendMH.setTransactionID(receiveMH.getTransactionID());

				// Mapped address attribute
				MappedAddress ma = new MappedAddress();
				ma.setAddress(new Address(((InetSocketAddress) src).getAddress().getAddress()));
				ma.setPort(((InetSocketAddress) src).getPort());
				sendMH.addMessageAttribute(ma);

				SourceAddress sa = new SourceAddress();
				sa.setAddress(new Address(SipService.getLocalIP()));
				sa.setPort(socket.socket().getLocalPort());
				sendMH.addMessageAttribute(sa);
				
				MessageAttribute usernameMA = receiveMH.getMessageAttribute(MessageAttributeType.Username);
				if (usernameMA != null) {
					sendMH.addMessageAttribute(usernameMA);

					byte [] data = sendMH.getBytes();
					socket.send(ByteBuffer.wrap(data), src);
				}
			}
			else if (receiveMH.getType() == MessageHeaderType.BindingResponse)
			{
				@SuppressWarnings("unused")
				Packet p = idTable.get(new ID(receiveMH.getTransactionID()));
				
				synchronized (transmitters)
				{
					if (   (this.jabberDest == null && socket == jabberSocket) 
					    || (this.jabberDestRtcp == null && socket == jabberSocketRtcp))
					{
						if (socket == jabberSocket)
						{
							this.jabberDest = src;
						}
						else
						{
							this.jabberDestRtcp = src;
						}

						Username user = (Username) receiveMH.getMessageAttribute(MessageAttributeType.Username);
						StunTransmitter newTimer = null;
						String newKey = null;
						for (String key : transmitters.keySet())
						{
							StunTransmitter st = transmitters.get(key);
							if (st.socket == socket)
							{
								try
								{
									st.cancel();
								}
								catch (Exception e)
								{
									
								}
								logger.debug("[[" + cs.internalCallId + "]] Comparing " + key + " to " + user.getUsername());
								if (user.getUsername().startsWith(key))
								{
									newKey = key;
									newTimer = new StunTransmitter(st.message, st.dest, st.socket);
								}
							}
						}

						if (newTimer != null && newKey != null)
						{
							logger.debug("[[" + cs.internalCallId + "]] ++++++++++++++++ slowing retransmission " + newKey + " ++++++++++++++");
							transmitters.put(newKey, newTimer);
							logger.debug("[[" + cs.internalCallId + "]] RtpRelay::StunTransmitter scheduled (slow) [" + jabberSocket.socket().getLocalPort() + "][" + sipSocket.socket().getLocalPort() + "] ==> " + newTimer.socket.socket().getLocalPort());
							retransTimer.schedule(newTimer, 100, 5000);
						}
					}
				}
			}			
		}
		catch (MessageHeaderParsingException e) 
		{
			// ignore (problem occurred in stun code)
		}
		catch (UnknownMessageAttributeException e) 
		{
			// ignore (problem occurred in stun code)
		}
		catch (MessageAttributeParsingException e) 
		{
			// ignore (problem occurred in stun code)
		}
		catch (UtilityException e) 
		{
			logger.error("Error in processStun", e);
		}
		catch (MessageAttributeException e) 
		{
			logger.error("Error in processStun", e);
		}
		catch (IOException e) 
		{
			logger.error("Error in processStun", e);
		}
		catch (ArrayIndexOutOfBoundsException e) 
		{
			// ignore (problem occurred in stun code)
		}
		catch (Exception e) 
		{
			logger.error("Error in processStun", e);
		}
	}

	/*
	 * Experimental. I believe that google uses special rtcp packets to send fast video updates - this is an unsuccessful
	 * attempt at implementing this feature.
	 */ 
	public void sendFIR()
	{
		byte [] buffer = new byte[20];
		RtpUtil.buildFIR(buffer, firSeq++, sipSSRC, jabberSSRC);
		
		try
		{
			jabberSocketRtcp.send(ByteBuffer.wrap(buffer), jabberDestRtcp);
		}
		catch (Exception e)
		{
			logger.error("Error sending FIR packet!", e);
		}
	}

	public void sendSipDTMF(char dtmf)
	{
		switch (dtmf)
		{
			case '0' :
			case '1' :
			case '2' :
			case '3' :
			case '4' :
			case '5' :
			case '6' :
			case '7' :
			case '8' :
			case '9' :
			case '*' :
			case '#' :
			case 'A' :
			case 'B' :
			case 'C' :
			case 'D' :
				logger.debug("[[" + cs.internalCallId + "]] Logging dtmf " + dtmf + " for generation");
				try
				{
					dtmfQueue.put(dtmf);
				} 
				catch (InterruptedException e)
				{
					logger.error("Interrupted why queueing a dtmf", e);
				}
				break;
			default :
				logger.warn("[[" + cs.internalCallId + "]] Ignoring invalid dtmf " + dtmf);
		}
	}
	
	public void run()
	{
		logger.info("[[" + cs.internalCallId + "]] RtpRelay Thread Started");
		
		Selector sel = null;
		
		try
		{
			sel = SelectorProvider.provider().openSelector();
			sipSocket.configureBlocking(false);
			sipSocketRtcp.configureBlocking(false);
			jabberSocket.configureBlocking(false);
			jabberSocketRtcp.configureBlocking(false);
			
			sipSocket.register(sel, SelectionKey.OP_READ);
			jabberSocket.register(sel, SelectionKey.OP_READ);
			sipSocketRtcp.register(sel, SelectionKey.OP_READ);
			jabberSocketRtcp.register(sel, SelectionKey.OP_READ);
		
			ByteBuffer inputBuffer = ByteBuffer.allocate(20000);
			ByteBuffer outputBuffer = ByteBuffer.allocate(20000);
			byte [] outputBytes = new byte[20000];
			
			while (sipSocket.isOpen())
			{
				 if (sel.select(1000) >= 0)
				 {
					Iterator<SelectionKey> itr = sel.selectedKeys().iterator();
					while (itr.hasNext()) 
					{
						SelectionKey key = itr.next();
						itr.remove();
						
						if (key.isValid() && key.isReadable())
						{
							DatagramChannel socket = (DatagramChannel) key.channel();
							inputBuffer.clear();

							if (!socket.isOpen()) 
							{
								logger.error("[[" + cs.internalCallId + "]] Socket is not open ... ignoring");
								continue;
							}
							
							SocketAddress src = socket.receive(inputBuffer);
							if (src == null) 
							{
								logger.error("[[" + cs.internalCallId + "]] Src is null ... ignoring");
								continue;
							}
							
							if ((inputBuffer.get(0) & 0x80) != 0)
							{
								DatagramChannel destSocket;
								SocketAddress destAddr;
								inputBuffer.flip();

								if (socket == sipSocket)
								{
									destSocket = jabberSocket;
									destAddr = jabberDest;
									
									if (this.sipSSRC == null)
									{
										this.sipSSRC = RtpUtil.getSSRC(inputBuffer.array());
									}
									
									if (destSocket != null && destAddr != null)
									{
										destSocket.send(inputBuffer, destAddr);
									}
								}
								else if (socket == sipSocketRtcp)
								{
									destSocket = jabberSocketRtcp;
									destAddr = jabberDestRtcp;
									
									if (destSocket != null && destAddr != null)
									{
										destSocket.send(inputBuffer, destAddr);
									}
								}
								else if (socket == jabberSocketRtcp)
								{
									destSocket = sipSocketRtcp;
									destAddr = sipDestRtcp;
									
									if (destSocket != null && destAddr != null)
									{
										destSocket.send(inputBuffer, destAddr);
									}

									if (video && System.currentTimeMillis() - lastVUpate > 5000)
									{
										SipService.sendVideoUpdate(this.cs);
										lastVUpate = System.currentTimeMillis();
									}
								}
								else
								{
									destSocket = sipSocket;
									destAddr = sipDest;

									if (this.jabberSSRC == null)
									{
										this.jabberSSRC = RtpUtil.getSSRC(inputBuffer.array());
									}

									synchronized (destSocket)
									{
										if (destSocket != null && destAddr != null)
										{
											if (!video)
											{
												this.jabberTimestamp = RtpUtil.getTimeStamp(inputBuffer.array());
												RtpUtil.setSequenceNumber(inputBuffer.array(), ++this.jabberSequence);
												if (destSocket.isOpen())
												{
													destSocket.send(inputBuffer, destAddr);
												}
											}
											else
											{
												// TODO: google uses H264 SVC, the rest of the world uses AVC, so convert
												// google now supports AVC so we should adapt to that
												
												int length = RtpUtil.filterSVC(inputBuffer.array(), outputBytes, inputBuffer.remaining());
												outputBuffer.clear();
												outputBuffer.put(outputBytes, 0, length);
												outputBuffer.flip();
												if (destSocket.isOpen())
												{
													destSocket.send(outputBuffer, destAddr);
												}
											}
										}
									}
								}
							}
							else
							{
								this.processStun(src, inputBuffer.array(), socket);
							}
						}
					}
				}
			}
		} 
		catch (IOException e)
		{
			logger.error("Error in RTP relay thread!", e);
		}
		catch (Exception e)
		{
			logger.error("Error in RTP relay thread!", e);
		}
		finally
		{
			if (sel != null)
			{
				try
				{
					sel.close();
				} 
				catch (IOException e)
				{
					// ignore (we're dead anyhow)
				}
			}
		}
		
		logger.info("[[" + cs.internalCallId + "]] RtpRelay Thread Stopped");
	}
	
	public void setSipDest(String host, int port)
	{
		this.sipDest = new InetSocketAddress(host, port);
		this.sipDestRtcp = new InetSocketAddress(host, port + 1);
	}
	
	public int getSipPort()
	{
		return this.sipSocket.socket().getLocalPort();
	}
	
	public int getSipRtcpPort()
	{
		return this.sipSocketRtcp.socket().getLocalPort();
	}
	
	public int getJabberPort()
	{
		return this.jabberSocket.socket().getLocalPort();
	}
	
	public int getJabberRtcpPort()
	{
		return this.jabberSocketRtcp.socket().getLocalPort();
	}
	
	public void shutdown()
	{
		logger.debug("[[" + cs.internalCallId + "]] Shutdown of rtp thread requested");
		synchronized (transmitters)
		{
			logger.debug("[[" + cs.internalCallId + "]] number of transmitters : " + transmitters.size());
			for (String key : transmitters.keySet())
			{
				logger.debug("[[" + cs.internalCallId + "]] cancelling transmitter : " + key);
				transmitters.get(key).cancel();
			}
		}
		
		try
		{
			dtmfQueue.put('\0');
		} 
		catch (InterruptedException e)
		{
			logger.error("unable to queue shutdown signal!", e);
		}
		
		try
		{
			sipSocket.close();
		} 
		catch (IOException e)
		{
			logger.error("unable to close sip-side rtp socket!", e);
		}
		try
		{
			jabberSocket.close();
		} 
		catch (IOException e)
		{
			logger.error("unable to close xmpp-side rtp socket!", e);
		}
		
		try
		{
			sipSocketRtcp.close();
		} 
		catch (IOException e)
		{
			logger.error("Error in rtcp shutdown", e);
		}
		try
		{
			jabberSocketRtcp.close();
		} 
		catch (IOException e)
		{
			logger.error("Error in rtcp shutdown", e);
		}
	}
}
