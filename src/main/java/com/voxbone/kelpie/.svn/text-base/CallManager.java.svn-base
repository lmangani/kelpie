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


import java.util.Hashtable;

import org.jabberstudio.jso.JID;


/**
 * 
 * Call Manager is used to track ongoing calls, we only look up by the jabber session id because the sip
 * side has a direct reference to the CallSession in its Dialog object
 *
 */
public class CallManager
{

	static Hashtable<String, CallSession> calls = new Hashtable<String, CallSession>();

	public static void addSession(CallSession cs)
	{
		calls.put(cs.jabberSessionId, cs);
	}

	public static CallSession getSession(String sid)
	{
		return calls.get(sid);
	}

	public static void removeSession(CallSession cs)
	{
		calls.remove(cs.jabberSessionId);
		cs.relay.shutdown();
		if (cs.vRelay != null)
		{
			cs.vRelay.shutdown();
		}
	}

	public static CallSession getSession(JID remote, JID local)
	{
		synchronized (calls)
		{
			for (CallSession cs : calls.values())
			{
				if (   cs.jabberRemote.toBareJID().match(remote)
				    && cs.jabberLocal.toBareJID().match(local))
				{
					return cs;
				}
			}
		}
		return null;
	}
}
