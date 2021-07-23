package com.ak.guard.model;

import io.micrometer.core.lang.Nullable;

public class ErrorInfo{
    @Nullable 
    private String errorCode;
    @Nullable
    private String errorMessage;
    @Nullable
    private ErrorInfo errorInfo;
    
    
	public String getErrorCode() {
		return errorCode;
	}


	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}


	public String getErrorMessage() {
		return errorMessage;
	}


	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}


	public ErrorInfo getErrorInfo() {
		return errorInfo;
	}


	public void setErrorInfo(ErrorInfo errorInfo) {
		this.errorInfo = errorInfo;
	}


	@Override
	public String toString() {
		return "ErrorInfo [errorCode=" + errorCode + ", errorMessage=" + errorMessage + ", errorInfo=" + errorInfo
				+ "]";
	} 
    
    
}

