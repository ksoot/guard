package com.ak.guard.integrity.models;

import java.security.PrivateKey;

public final class SignatureRequest {

	private final String payload;
	private final PrivateKey privateKey;
	
	public SignatureRequest(String payload, PrivateKey privateKey) {
		super();
		this.payload = payload;
		this.privateKey = privateKey;
	}
	
	public String getPayload() {
		return payload;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	
	
}
