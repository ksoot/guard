package com.ak.guard.model;

public class CipherResponse {

	private p_M M;
	private String sign;
	private String certificate;
	
	
	
	public CipherResponse(p_M m, String sign, String certificate) {
		super();
		M = m;
		this.sign = sign;
		this.certificate = certificate;
	}



	public p_M getP_M() {
		return M;
	}



	public String getSign() {
		return sign;
	}



	public String getCertificate() {
		return certificate;
	}



	@Override
	public String toString() {
		return "CipherResponse [M=" + M + ", sign=" + sign + ", certificate=" + certificate + "]";
	}
	
	

}
