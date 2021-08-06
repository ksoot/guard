package com.ak.guard.model;

public class CipherRequest {

	private String sign;
	private f_M M;

	public CipherRequest(String f_EncodedSignedMessage, f_M message) {
		this.M = message;
		this.sign = f_EncodedSignedMessage;

	}

	public String getSign() {
		return sign;
	}

	public f_M getf_M() {
		return M;
	}
	
	

}
