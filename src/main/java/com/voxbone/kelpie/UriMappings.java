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


import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.jabberstudio.jso.JID;

/**
 * Mapping of jabber ids to telephone numbers, usefull if you want to also want communicaton
 * from SIP -> XMPP direction
 *
 */
public class UriMappings
{
	private static List<Mapping> mappings = new ArrayList<Mapping>();
	private static Logger log = Logger.getLogger(UriMappings.class);
	private static String host;
	private static String fakeId;
	
	private static class Mapping
	{
		public String sip_id;
		public JID jid;
		public String voiceResource;

		public Mapping(String sip_id, JID jid)
		{
			this.sip_id = sip_id;
			this.jid = jid;
			this.voiceResource = null;
		}
	}
	
	public static void configure(Properties properties) {
		fakeId = properties.getProperty("com.voxbone.kelpie.service_name", "kelpie");
		buildMap(properties);
	}
	
	public static void initialize()
	{
		for (Mapping m : mappings)
		{
			Session sess = SessionManager.findCreateSession(host, m.jid);		
			sess.sendSubscribeRequest(new JID(fakeId + "@" + host), m.jid, "subscribe");
		}
	}

	public static void buildMap(Properties p)
	{
		host = p.getProperty("com.voxbone.kelpie.hostname");
		for (Object okey : p.keySet())
		{
			String key = (String) okey;
			if (key.startsWith("com.voxbone.kelpie.mapping"))
			{
				String sip_id = key.substring("com.voxbone.kelpie.mapping.".length());				
				JID jid = new JID((String) p.get(key));
				log.debug("Adding " + sip_id + " => " + jid);
				mappings.add(new Mapping(sip_id, jid));
			}
		}
	}
	
	public static JID toJID(String sip_id)
	{
		for (Mapping m : mappings)
		{
			if (m.sip_id.equals(sip_id))
			{
				return m.jid;
			}
		}
		
		if (sip_id.contains("+"))
		{
			String [] fields = sip_id.split("\\+", 2);
			return new JID(fields[0] + "@" + fields[1]);
		}

		return null;
	}
	
	public static String toSipId(JID jid)
	{
		for (Mapping m : mappings)
		{
			if (m.jid.match(jid))
			{
				return m.sip_id;
			}
		}
		return jid.getNode() + "+" + jid.getDomain();
	}
	
	public static void addVoiceResource(JID jid)
	{
		for (Mapping m : mappings)
		{
			if (m.jid.match(jid))
			{
				m.voiceResource = jid.getResource();
				log.info("Resource set to " + jid.getResource());
			}
		}
	}
	
	public static String getVoiceResource(JID jid)
	{
		for (Mapping m : mappings)
		{
			if (m.jid.match(jid))
			{
				return m.voiceResource;
			}
		}
		return null;
	}
}
