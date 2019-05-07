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

package it.unipr.netsec.ipstack.analyzer;


import java.util.Vector;


/** Generic protocol field.
  */
public class ProtocolField {
	
	/** Tab string used for the sub-field indentation */
	public static String TAB="   ";

	/** Field name */
	String name;

	/** Field value */
	String value;

	/** Sub-fields */
	Vector<ProtocolField> subfields;


	/** Creates a new ProtocolField.
	  * @param name field name
	  * @param value field value */
	public ProtocolField(String name, String value) {
		this.name=name;
		this.value=value;
		this.subfields=null;
	}

	/** Creates a new ProtocolField.
	  * @param name field name
	  * @param value field value
	  * @param subfields Sub-fields */
	public ProtocolField(String name, String value, Vector<ProtocolField> subfields) {
		this.name=name;
		this.value=value;
		this.subfields=subfields;
	}

	/** Adds a sub-field.
	  * @param subfield the sub-field to be added */
	public void addSubField(ProtocolField subfield) {
		if (subfields==null) subfields=new Vector<ProtocolField>();
		subfields.addElement(subfield);
	}

	/** Adds a sub-field.
	  * @param name sub-field name
	  * @param value sub-field value */
	public void addSubField(String name, String value) {
		addSubField(new ProtocolField(name,value));
	}

	/** Gets field name. */
	public String getName() {
		return name;
	}

	/** Gets field value. */
	public String getValue() {
		return value;
	}

	/** Whether has sub-fields. */
	public boolean hasSubFields() {
		return (subfields!=null && subfields.size()>0);
	}

	/** Gets sub-fields. */
	public Vector<ProtocolField> getSubFields() {
		if (subfields==null) subfields=new Vector<ProtocolField>();
		return subfields;
	}  
	
	/** Gets a string representation of this object.
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	@Override
	public String toString() {
		return toTabString(0,-1);
	}

	/** Gets a string representation of this object.
	  * @param max_level maximum level of indentation (-1 for infinite indentation)
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	public String toString(int max_level) {
		return toTabString(0,max_level);
	}

	/** Gets a string representation of this object.
	  * @param level current level of indentation
	  * @param max_level maximum level of indentation (-1 for infinite indentation)
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	private String toTabString(int level, int max_level) {
		StringBuffer sb=new StringBuffer();
		for (int i=0; i<level; i++) sb.append(TAB);
		//sb.append(field).append('\n');
		sb.append(name).append(": ").append(value);
		if (subfields!=null && (max_level<0 || level<max_level)) {
			level++;
			//for (int i=0; i<subfields.size(); i++) sb.append(subfields.elementAt(i).toTabString(level,max_level));
			for (int i=0; i<subfields.size(); i++) sb.append('\n').append(((ProtocolField)subfields.elementAt(i)).toTabString(level,max_level));
		}
		return sb.toString();
	}

}
