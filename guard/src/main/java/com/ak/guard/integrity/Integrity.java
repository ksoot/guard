package com.ak.guard.integrity;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import com.ak.guard.integrity.models.SignatureRequest;
import com.ak.guard.integrity.models.VerificationRequest;

public interface Integrity {

	public byte[] SignatureGeneration(SignatureRequest signatureRequest)
			throws NoSuchAlgorithmException, SignatureException;

	public boolean SignatureVerification(VerificationRequest verificationRequest)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
	
}
