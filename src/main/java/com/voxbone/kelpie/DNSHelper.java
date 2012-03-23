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


import org.xbill.DNS.*;

import java.util.*;
import java.util.logging.Logger;

/**
 * Class used to perform DNS SRV resolution
 *
 */

public class DNSHelper
{
	
	public static Logger logger = Logger.getLogger(DNSHelper.class.getName());


	public static ArrayList<String> getSRVServerList(String domain, String serviceProtocol, String transportProtocol) throws Exception 
	{
		Record [] records = new Lookup("_" + serviceProtocol + "." + "_" + transportProtocol + "." + domain, Type.SRV).run();
		if (records == null) 
		{
			return null;
		}

		HashMap<Integer,Integer> map = new HashMap<Integer,Integer>();
		int leastPriority = 0;
		for (int i = 0; i < records.length; i++) 
		{
			SRVRecord srv = (SRVRecord) records[i];
			int priority = srv.getPriority();
			if (i == 0 || priority < leastPriority)
			{
				leastPriority = priority;
			}

			if (map.containsKey(priority)) 
			{
				map.put(priority, map.get(priority) + srv.getWeight());
			} 
			else 
			{
				map.put(priority, srv.getWeight());
			}
		}

		ArrayList<SRVRecord> prilist = new ArrayList<SRVRecord>();
		ArrayList<SRVRecord> lowlist = new ArrayList<SRVRecord>();
		for (int i = 0; i < records.length; i++) 
		{
			if (((SRVRecord) records[i]).getPriority() != leastPriority) 
			{
				lowlist.add((SRVRecord) records[i]);
			}
			else
			{
				prilist.add((SRVRecord) records[i]);
			}
		}

		ArrayList<String> result = new ArrayList<String>();
		
		for (SRVRecord rec : prilist)
		{
			String server = rec.getTarget().toString();
			server = server.substring(0, server.length() - 1);
			server += ":" + rec.getPort();
			result.add(server);
		}
		
		for (SRVRecord rec : lowlist)
		{
			String server = rec.getTarget().toString();
			server = server.substring(0, server.length() - 1);
			server += ":" + rec.getPort();
			result.add(server);
		}

		return result;
	}

	public static String resolveToIP(String domainName) throws TextParseException 
	{
		String targetIP;
		Record [] records = (new Lookup(domainName, Type.A)).run();
		if (records != null && records.length > 0)
		{
			targetIP = ((ARecord) records[0]).getAddress().getHostAddress();
		} 
		else 
		{
			targetIP = null;
		}
		return targetIP;
	}

}
