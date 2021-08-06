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
public class f_M {

	private String dh_params; //AES Parameter
	private String dhpk;
	private byte[] rand; // UUID as string.
	private String jsonRequest;
	
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
	public byte[] getRand() {
		return rand;
	}
	public void setRand(byte[] rand) {
		this.rand = rand;
	}
	
	public String getJsonRequest() {
		return jsonRequest;
	}
	
	public void setJsonRequest(String jsonRequest) {
		this.jsonRequest = jsonRequest;
	}
	@Override
	public String toString() {
		return "f_M [dh_params=" + dh_params + ", dhpk=" + dhpk + ", rand=" + rand + ", jsonRequest=" + jsonRequest
				+ "]";
	}
	
	
}
