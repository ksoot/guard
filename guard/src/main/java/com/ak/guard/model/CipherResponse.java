package com.ak.guard.model;

import io.micrometer.core.lang.Nullable;
import lombok.NonNull;

public class CipherResponse {
	@NonNull
	String base64Data;
	@Nullable
	ErrorInfo errorInfo;

	public CipherResponse() {
		// TODO Auto-generated constructor stub
	}

	public CipherResponse(String base64Data, ErrorInfo errorInfo) {
		super();
		this.base64Data = base64Data;
		this.errorInfo = errorInfo;
	}

	public String getBase64Data() {
		return base64Data;
	}

	public void setBase64Data(String base64Data) {
		this.base64Data = base64Data;
	}

	public ErrorInfo getErrorInfo() {
		return errorInfo;
	}

	public void setErrorInfo(ErrorInfo errorInfo) {
		this.errorInfo = errorInfo;
	}

	@Override
	public String toString() {
		return "CipherResponse [base64Data=" + base64Data + ", errorInfo=" + errorInfo + "]";
	}

}
