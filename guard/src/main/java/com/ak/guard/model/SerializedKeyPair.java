package com.ak.guard.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.micrometer.core.lang.Nullable;
import lombok.NonNull;

public class SerializedKeyPair{
   
	@NonNull
    private String privateKey;
    @NonNull
    @JsonProperty("KeyMaterial")
    KeyMaterial keyMaterial;
    @Nullable
    ErrorInfo errorInfo;
    
    public SerializedKeyPair() {
	}
    
    public SerializedKeyPair(String privateKey, KeyMaterial keyMaterial) {
		super();
		this.privateKey = privateKey;
		this.keyMaterial = keyMaterial;
	}
    
	public SerializedKeyPair(String privateKey, KeyMaterial keyMaterial, ErrorInfo errorInfo) {
		super();
		this.privateKey = privateKey;
		this.keyMaterial = keyMaterial;
		this.errorInfo = errorInfo;
	}



	@Override
	public String toString() {
		return "SerializedKeyPair [privateKey=" + privateKey + ", keyMaterial=" + keyMaterial + ", errorInfo="
				+ errorInfo + "]";
	}
	
	public String getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}
	public KeyMaterial getKeyMaterial() {
		return keyMaterial;
	}
	public void setKeyMaterial(KeyMaterial keyMaterial) {
		this.keyMaterial = keyMaterial;
	}
	public ErrorInfo getErrorInfo() {
		return errorInfo;
	}
	public void setErrorInfo(ErrorInfo errorInfo) {
		this.errorInfo = errorInfo;
	}
}

