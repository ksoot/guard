package com.ak.guard.integrity;

import static com.ak.guard.common.GuardConstants.ECC_ALGO;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ak.guard.common.CommonUtil;
import com.ak.guard.integrity.models.SignatureRequest;
import com.ak.guard.integrity.models.VerificationRequest;

public class Ed25519Integrity implements Integrity {

	private static Logger log = Logger.getLogger("Ed25519Integrity");

	@Override
	public byte[] SignatureGeneration(SignatureRequest signatureRequest)
			throws NoSuchAlgorithmException, SignatureException {
		log.log(Level.INFO, "Generating Digital Signature using Algo : " + ECC_ALGO);
		Signature sign = null;
		try {
			sign = Signature.getInstance(ECC_ALGO);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Problem initializing " + ECC_ALGO);
			throw e;
		}

		try {
			sign.initSign(signatureRequest.getPrivateKey());
		} catch (InvalidKeyException e) {
			System.out.println("Exception: While signing using " + ECC_ALGO);
			System.out.println(e.getMessage());
		}

		try {
			sign.update(signatureRequest.getPayload().getBytes());
		} catch (SignatureException e) {
			System.out.println("Exception: While updating plaintext message ");
			throw e;
		}

		byte[] signArray = new byte[0];

		try {
			signArray = sign.sign();
		} catch (SignatureException e) {
			System.out.println("Exception: while signing using " + ECC_ALGO);
			throw e;
		}
		System.out.println("signature :" + CommonUtil.bytesAsString(signArray));
		log.log(Level.INFO, "Successfully generated Digital Signature using Algo : " + ECC_ALGO);
		return CommonUtil.encodedBytes(signArray);
	}

	@Override
	public boolean SignatureVerification(VerificationRequest verificationRequest)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		log.log(Level.INFO, "Vefifying Digital Signature using Algo : " + ECC_ALGO);
		Signature verify = null;
		try {
			verify = Signature.getInstance(ECC_ALGO);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception: While initializing " + ECC_ALGO);
			throw e;
		}

		try {
			verify.initVerify(verificationRequest.getPublicKey());
		} catch (InvalidKeyException e) {
			System.out.println("Exception: While initializing with Public Key for usage with " + ECC_ALGO);
			throw e;
		}

		try {
			verify.update(verificationRequest.getPayload().getBytes());
		} catch (SignatureException e) {
			System.out.println("Exception : While updating with message");
			throw e;
		}

		boolean isVerified = false;

		try {
			isVerified = verify.verify(CommonUtil.decodedBytes(verificationRequest.getEncodedSign()));
		} catch (SignatureException e) {
			System.out.println("Exception: While, verifying signature");
		}
		System.out.println("isVerified : " + isVerified);
		log.log(Level.INFO, "Successfully verified Digital Signature using Algo : " + ECC_ALGO);
		return isVerified;
	}

}
