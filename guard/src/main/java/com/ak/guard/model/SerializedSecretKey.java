package com.ak.guard.model;

import io.micrometer.core.lang.Nullable;
import lombok.NonNull;


public class SerializedSecretKey{

    @NonNull
    private String key;
    @Nullable
    ErrorInfo errorInfo;
    
	public SerializedSecretKey(String key) {
		this.key = key;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public ErrorInfo getErrorInfo() {
		return errorInfo;
	}
	public void setErrorInfo(ErrorInfo errorInfo) {
		this.errorInfo = errorInfo;
	}
	
	@Override
	public String toString() {
		return "SerializedSecretKey [key=" + key + ", errorInfo=" + errorInfo + "]";
	}
    
    
}

