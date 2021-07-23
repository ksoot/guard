package com.ak.guard.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.NonNull;

public class KeyMaterial {

	@NonNull
	String cryptoAlg;
	@NonNull
	String curve;
	@NonNull
	String params;
	@NonNull
	@JsonProperty("DHPublicKey")
	DHPublicKey dhPublicKey;

	public KeyMaterial() {
		// TODO Auto-generated constructor stub
	}

	public KeyMaterial(String cryptoAlg, String curve, String params, DHPublicKey dhPublicKey) {
		super();
		this.cryptoAlg = cryptoAlg;
		this.curve = curve;
		this.params = params;
		this.dhPublicKey = dhPublicKey;
	}

	public String getCryptoAlg() {
		return cryptoAlg;
	}

	public void setCryptoAlg(String cryptoAlg) {
		this.cryptoAlg = cryptoAlg;
	}

	public String getCurve() {
		return curve;
	}

	public void setCurve(String curve) {
		this.curve = curve;
	}

	public String getParams() {
		return params;
	}

	public void setParams(String params) {
		this.params = params;
	}

	public DHPublicKey getDhPublicKey() {
		return dhPublicKey;
	}

	public void setDhPublicKey(DHPublicKey dhPublicKey) {
		this.dhPublicKey = dhPublicKey;
	}

	@Override
	public String toString() {
		return "KeyMaterial [cryptoAlg=" + cryptoAlg + ", curve=" + curve + ", params=" + params + ", dhPublicKey="
				+ dhPublicKey + "]";
	}

}
