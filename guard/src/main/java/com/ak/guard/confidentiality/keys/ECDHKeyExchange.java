package com.ak.guard.confidentiality.keys;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import com.ak.guard.common.CommonUtil;
import com.ak.guard.common.GuardConstants;

public class ECDHKeyExchange implements KeyExchange{

	private static Logger log = Logger.getLogger("ECDHKeyExchange");
	

	@Override
	public byte[] DHSharedKeyAlgo(final PublicKey publicKey, final PrivateKey privateKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		log.log(Level.INFO, "Creating the secret key");
		KeyAgreement ecdhKeyAgreement = KeyAgreement.getInstance(GuardConstants.KEY_EXCHANGE_ALGO,
				GuardConstants.JCA_PROVIDER);
		ecdhKeyAgreement.init(privateKey);
		ecdhKeyAgreement.doPhase(publicKey, true);
		final byte[] secretKey = ecdhKeyAgreement.generateSecret();
		System.out.println("secret key :" + CommonUtil.bytesAsString(secretKey));
		log.log(Level.INFO, "Successfully created the secret key");
		return CommonUtil.encodedBytes(secretKey);
	}

	@Override
	public byte[] GenerateSessionKeyAlgo(final byte[] encodedSecretKey, final byte[] encodedOriginNonce, final byte[] encodedRemoteNonce)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		log.log(Level.INFO, "Creating session key");
		
		final byte[] out = CommonUtil.xored(encodedOriginNonce, encodedRemoteNonce);
		final byte[] salt = new byte[20];
		System.arraycopy(out, 0, salt, 0, 20);
		HKDFParameters hkdf = new HKDFParameters(CommonUtil.decodedBytes(encodedSecretKey), salt, null);
		HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
		generator.init(hkdf);
		byte[] result = new byte[32];
		generator.generateBytes(result, 0, 32);
		System.out.println("session key :" + CommonUtil.bytesAsString(result));
		log.log(Level.INFO, "Successfully created session key");
		return CommonUtil.encodedBytes(result);
	}

}
