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


import org.apache.log4j.Logger;
import org.jabberstudio.jso.event.StreamStatusEvent;
import org.jabberstudio.jso.event.StreamStatusListener;


public class StatusMonitor implements StreamStatusListener 
{
	
	private String internalCallId;

	public StatusMonitor(String internalCallId) 
	{
		this.internalCallId = internalCallId;
	}
	
	protected Logger obtainLogger() 
	{
		return Logger.getLogger(getClass());
	}
	
	public void statusChanged(StreamStatusEvent evt) 
	{
		Logger log = obtainLogger();
		Exception e = evt.getException();

		if (log.isInfoEnabled())
		{
			log.debug("[[" + internalCallId + "]] " + (evt.getContext().isInbound() ? "Inbound" : "Outbound") + " Status Change:  " + evt.getPreviousStatus() + " --> " + evt.getNextStatus());
		}
		if (e != null) 
		{
			log.error("[[" + internalCallId + "]] Error during status change", e);
		}
	}
}
