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

package it.unipr.netsec.ipstack.net;



/** Generic address.
 */
public interface Address {

	@Override
	public boolean equals(Object o);

	
	@Override
	public int hashCode();

	
	@Override
	public String toString();

	
	/** Gets the address length.
	 * @return the number of bytes the form this address */
	//public int length();


	/** Gets the address as byte array.
	 * @return the byte array containing the address */
	public byte[] getBytes();


	/** Gets the address as byte array.
	 * @param buf the byte array where the address is going to be written
	 * @param off the offset within the buffer
	 * @return the number of bytes */
	public int getBytes(byte[] buf, int off);

}
