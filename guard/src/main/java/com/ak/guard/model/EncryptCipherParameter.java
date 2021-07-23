package com.ak.guard.model;

import lombok.NonNull;


public class EncryptCipherParameter {
	
	@NonNull
	KeyMaterial remoteKeyMaterial;
	@NonNull
	String originPrivateKey;
	@NonNull
	String base64OriginNonce;
	@NonNull
	String base64RemoteNonce;
	@NonNull
	String data;

	
	public EncryptCipherParameter() {
	}

	public EncryptCipherParameter(KeyMaterial remoteKeyMaterial, String originPrivateKey, String base64OriginNonce,
			String base64RemoteNonce, String data) {
		super();
		this.remoteKeyMaterial = remoteKeyMaterial;
		this.originPrivateKey = originPrivateKey;
		this.base64OriginNonce = base64OriginNonce;
		this.base64RemoteNonce = base64RemoteNonce;
		this.data = data;
	}

	
	public KeyMaterial getRemoteKeyMaterial() {
		return remoteKeyMaterial;
	}

	public void setRemoteKeyMaterial(KeyMaterial remoteKeyMaterial) {
		this.remoteKeyMaterial = remoteKeyMaterial;
	}

	public String getBase64OriginNonce() {
		return base64OriginNonce;
	}
	
	public void setBase64OriginNonce(String base64OriginNonce) {
		this.base64OriginNonce = base64OriginNonce;
	}
	
	public String getOriginPrivateKey() {
		return originPrivateKey;
	}
	
	public void setOriginPrivateKey(String originPrivateKey) {
		this.originPrivateKey = originPrivateKey;
	}

	public String getBase64RemoteNonce() {
		return base64RemoteNonce;
	}

	public void setBase64RemoteNonce(String base64RemoteNonce) {
		this.base64RemoteNonce = base64RemoteNonce;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	@Override
	public String toString() {
		return "EncryptCipherParameter [remoteKeyMaterial=" + remoteKeyMaterial + ", originPrivateKey="
				+ originPrivateKey + ", base64OriginNonce=" + base64OriginNonce + ", base64RemoteNonce="
				+ base64RemoteNonce + ", data=" + data + "]";
	}

}
