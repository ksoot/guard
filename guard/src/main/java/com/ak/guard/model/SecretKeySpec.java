package com.ak.guard.model;

import lombok.NonNull;

public class SecretKeySpec {

	@NonNull
	String remotePublicKey;
	@NonNull
	String originPrivateKey;

	public SecretKeySpec() {
	}

	public SecretKeySpec(String remotePublicKey, String originPrivateKey) {
		super();
		this.remotePublicKey = remotePublicKey;
		this.originPrivateKey = originPrivateKey;
	}

	@Override
	public String toString() {
		return "SecretKeySpec [remotePublicKey=" + remotePublicKey + ", originPrivateKey=" + originPrivateKey + "]";
	}

	public String getRemotePublicKey() {
		return remotePublicKey;
	}

	public void setRemotePublicKey(String remotePublicKey) {
		this.remotePublicKey = remotePublicKey;
	}

	public String getOriginPrivateKey() {
		return originPrivateKey;
	}
	
	public void setOriginPrivateKey(String originPrivateKey) {
		this.originPrivateKey = originPrivateKey;
	}

}
