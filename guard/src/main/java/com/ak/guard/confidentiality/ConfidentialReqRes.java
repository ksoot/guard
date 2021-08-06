package com.ak.guard.confidentiality;

public final class ConfidentialReqRes {

	private byte[] encodedPlainText;
	private byte[] encodedCipherText;
	private final byte[] encodedSessionKey;
	private final byte[] encodedOriginNonce;
	private final byte[] encodedRemoteNonce;

	public ConfidentialReqRes(byte[] encodedPlainText, byte[] encodedCipherText, byte[] encodedSessionKey,
			byte[] encodedOriginNonce, byte[] encodedRemoteNonce) {
		super();
		this.encodedPlainText = encodedPlainText;
		this.encodedCipherText = encodedCipherText;
		this.encodedSessionKey = encodedSessionKey;
		this.encodedOriginNonce = encodedOriginNonce;
		this.encodedRemoteNonce = encodedRemoteNonce;
	}

	public byte[] getEncodedPlainText() {
		return encodedPlainText;
	}

	public void setEncodedPlainText(byte[] encodedPlainText) {
		this.encodedPlainText = encodedPlainText;
	}

	public byte[] getEncodedCipherText() {
		return encodedCipherText;
	}

	public void setEncodedCipherText(byte[] encodedCipherText) {
		this.encodedCipherText = encodedCipherText;
	}

	public byte[] getEncodedSessionKey() {
		return encodedSessionKey;
	}

	public byte[] getEncodedOriginNonce() {
		return encodedOriginNonce;
	}

	public byte[] getEncodedRemoteNonce() {
		return encodedRemoteNonce;
	}

}
