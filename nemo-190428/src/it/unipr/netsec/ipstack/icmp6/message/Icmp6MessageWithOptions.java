/*
 * Copyright 2018 NetSec Lab - University of Parma
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author(s):
 * Luca Veltri (luca.veltri@unipr.it)
 */

package it.unipr.netsec.ipstack.icmp6.message;


import java.util.ArrayList;
import java.util.Arrays;

import it.unipr.netsec.ipstack.icmp6.Icmp6Message;
import it.unipr.netsec.ipstack.icmp6.message.option.Icmp6Option;
import it.unipr.netsec.ipstack.ip6.Ip6Address;


/** ICMPv6 message with options.
 */
abstract class Icmp6MessageWithOptions extends Icmp6Message {

	/** Offset of the options within the message body */
	protected int opt_off;
	
	
	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param type ICMP message type
	 * @param code ICMP subtype code
	 * @param opt_off offset of the options within the message body
	 * @param options array of options */
	protected Icmp6MessageWithOptions(Ip6Address src_addr, Ip6Address dst_addr, int type, int code, int opt_off, Icmp6Option[] options) {
		super(src_addr,dst_addr,type,code);
		this.opt_off=opt_off;
		int len=opt_off;
		if (options!=null) for (Icmp6Option o : options) len+=o.getTotalLength();
		icmp_body=new byte[len];
		Arrays.fill(icmp_body,0,opt_off,(byte)0);
		int index=opt_off;
		if (options!=null) for (Icmp6Option o : options) index+=o.getBytes(icmp_body,index);
	}

	/** Creates a new ICMP message.
	 * @param src_addr IP source address
	 * @param dst_addr IP destination address
	 * @param opt_off offset of the options within the message body
	 * @param buf the buffer containing the ICMP message
	 * @param off the offset within the buffer
	 * @param len the length of the ICMP message */
	protected Icmp6MessageWithOptions(Ip6Address src_addr, Ip6Address dst_addr, int opt_off, byte[] buf, int off, int len) {
		super(src_addr,dst_addr,buf,off,len);
		this.opt_off=opt_off;
	}
	
	/** Creates a new ICMP message.
	 * @param msg the ICMP message
	 * @param opt_off offset of the options within the message body */
	protected Icmp6MessageWithOptions(Icmp6Message msg, int opt_off) {
		super(msg);
		this.opt_off=opt_off;
	}
		
	/** Gets options.
	 * @return array of options */
	public Icmp6Option[] getOptions() {
		ArrayList<Icmp6Option> options=new ArrayList<Icmp6Option>();
		int index=opt_off;
		if (index<icmp_body.length) {
			Icmp6Option o=Icmp6Option.parseOption(icmp_body,index);
			options.add(o);
			index+=o.getTotalLength();
		}
		return options.toArray(new Icmp6Option[]{});
	}

}
