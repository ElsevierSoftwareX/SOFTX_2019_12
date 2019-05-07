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

package it.unipr.netsec.ipstack.tcp.option;



/** Option. */
public interface Option {

	/** Gets the option type.
	 * @return the type */
	public int getType();

	
	/** Gets the option length.
	 * @return the length */
	public int getTotalLength();

	
	/** Gets a the option in a byte array.
	 * @param buf the buffer where the option has to be written
	 * @param off the offset within the buffer
	 * @return the option length */
	public int getBytes(byte[] buf, int off);

	
	/** Gets a the option in a byte array.
	 * @return a new byte array containing the option */
	public byte[] getBytes();

	
	/** Gets a string representation of this option.
	 * @return a string with the main information of this option */
	public String toString();

}
