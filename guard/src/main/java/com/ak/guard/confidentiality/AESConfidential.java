package com.ak.guard.confidentiality;

import static com.ak.guard.common.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_ALGO;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ak.guard.common.CachableSingletons;
import com.ak.guard.common.CommonUtil;
import com.ak.guard.common.GuardConstants;

public class AESConfidential implements Confidential {

	private static Logger log = Logger.getLogger("AESConfidential");
	
	@Override
	public ConfidentialReqRes FIDataEncrypt(ConfidentialReqRes confidentialReqRes)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		log.info("Encrypting message");

		Cipher cipher = initCipher(confidentialReqRes, Cipher.ENCRYPT_MODE);
		byte[] cipherData = cipher.doFinal(CommonUtil.decodedBytes(confidentialReqRes.getEncodedPlainText()));
		System.out.println("cipher text :" + CommonUtil.bytesAsString(cipherData));
		confidentialReqRes.setEncodedCipherText(CommonUtil.encodedBytes(cipherData));
		log.log(Level.INFO, "Successfully encrypted the message:");
		return confidentialReqRes;

	}

	@Override
	public ConfidentialReqRes FIDataDecrypt(ConfidentialReqRes confidentialReqRes)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		log.info("Decrypting message");

		Cipher cipher = initCipher(confidentialReqRes, Cipher.DECRYPT_MODE);
		byte[] plainData = cipher.doFinal(CommonUtil.decodedBytes(confidentialReqRes.getEncodedCipherText()));
		System.out.println("plain text :" + CommonUtil.bytesAsString(plainData));
		confidentialReqRes.setEncodedPlainText(CommonUtil.encodedBytes(plainData));
		log.log(Level.INFO, "Successfully decrypted the message:");
		return confidentialReqRes;

	}

	private Cipher initCipher(ConfidentialReqRes confidentialReqRes, int mode) throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		final int gcmTagLength = 16;
		Cipher cipher = Cipher.getInstance(GuardConstants.CIPHER_ALGO, GuardConstants.JCA_PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(CommonUtil.decodedBytes(confidentialReqRes.getEncodedSessionKey()),
				SYMMETRIC_CRYPTO_CIPHER_ALGO);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gcmTagLength * 8,
				generateIV(confidentialReqRes.getEncodedOriginNonce(), confidentialReqRes.getEncodedRemoteNonce()));
		cipher.init(mode, keySpec, gcmParameterSpec, CachableSingletons.drbg256Random());
		return cipher;
	}

	private byte[] generateIV(final byte[] encodedOriginNonce, final byte[] encodedRemoteNonce) {
		final int ivLength = 12;
		final int saltIVOffset = 20;
		byte[] iv = new byte[12];
		byte[] out = CommonUtil.xored(encodedOriginNonce, encodedRemoteNonce);
		System.arraycopy(out, saltIVOffset, iv, 0, ivLength);
		return iv;
	}

}
