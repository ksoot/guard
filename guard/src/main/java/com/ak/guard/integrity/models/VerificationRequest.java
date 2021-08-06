package com.ak.guard.integrity.models;

import java.security.PublicKey;

public final class VerificationRequest {

	private final String payload;
	private final PublicKey publicKey;
	private final byte[] encodedSign;

	public VerificationRequest(String payload, PublicKey publicKey, byte[] encodedSign) {
		super();
		this.payload = payload;
		this.publicKey = publicKey;
		this.encodedSign = encodedSign;
	}

	public String getPayload() {
		return payload;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public byte[] getEncodedSign() {
		return encodedSign;
	}

}
