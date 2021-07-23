package com.ak.guard.model;

import lombok.NonNull;

public class DecryptCipherParameter {

	@NonNull
	KeyMaterial remoteKeyMaterial;
	@NonNull
	String originPrivateKey;
	@NonNull
	String base64OriginNonce;
	@NonNull
	String base64RemoteNonce;
	@NonNull
	String base64Data;

	public DecryptCipherParameter() {
		// TODO Auto-generated constructor stub
	}

	public DecryptCipherParameter(KeyMaterial remoteKeyMaterial, String originPrivateKey, String base64OriginNonce,
			String base64RemoteNonce, String base64Data) {
		super();
		this.remoteKeyMaterial = remoteKeyMaterial;
		this.originPrivateKey = originPrivateKey;
		this.base64OriginNonce = base64OriginNonce;
		this.base64RemoteNonce = base64RemoteNonce;
		this.base64Data = base64Data;
	}

	public KeyMaterial getRemoteKeyMaterial() {
		return remoteKeyMaterial;
	}

	public void setRemoteKeyMaterial(KeyMaterial remoteKeyMaterial) {
		this.remoteKeyMaterial = remoteKeyMaterial;
	}

	

	public String getBase64RemoteNonce() {
		return base64RemoteNonce;
	}

	public void setBase64RemoteNonce(String base64RemoteNonce) {
		this.base64RemoteNonce = base64RemoteNonce;
	}

	public String getBase64Data() {
		return base64Data;
	}

	public void setBase64Data(String base64Data) {
		this.base64Data = base64Data;
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

	@Override
	public String toString() {
		return "DecryptCipherParameter [remoteKeyMaterial=" + remoteKeyMaterial + ", originPrivateKey="
				+ originPrivateKey + ", base64OriginNonce=" + base64OriginNonce + ", base64RemoteNonce="
				+ base64RemoteNonce + ", base64Data=" + base64Data + "]";
	}
	
	

}
