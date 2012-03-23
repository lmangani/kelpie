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


import java.util.Enumeration;
import java.util.Properties;
import java.util.ResourceBundle;

/**
 * Class to read in a java properties file
 *
 */
public final class ConfigurationUtil 
{
	private ConfigurationUtil()
	{
		
	}
	
	public static Properties getPropertiesResource(String name) 
	{
		Properties props = new Properties();
		
		ResourceBundle rb = ResourceBundle.getBundle(name);
		Enumeration<String> keys = rb.getKeys();
		
		while (keys.hasMoreElements()) 
		{
			String key = keys.nextElement();
			props.setProperty(key, rb.getString(key));
		}
		
		return props;
	}
}
