/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ak.guard.model;

/**
 * @author praveenp
 *
 */
public class p_M {

	private String dh_params; // AES Parameter
	private String dhpk;
	private String rand; // UUID as string.
	private String status;
	private byte[] cipherText;
	
	public String getDh_params() {
		return dh_params;
	}
	public void setDh_params(String dh_params) {
		this.dh_params = dh_params;
	}
	public String getDhpk() {
		return dhpk;
	}
	public void setDhpk(String dhpk) {
		this.dhpk = dhpk;
	}
	public String getRand() {
		return rand;
	}
	public void setRand(String rand) {
		this.rand = rand;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public byte[] getCipherText() {
		return cipherText;
	}
	public void setCipherText(byte[] cipherText) {
		this.cipherText = cipherText;
	}

	
}
