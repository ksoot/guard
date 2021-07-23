package com.ak.guard;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;

public final class X25519KeyExchange implements IKeyExchange {

	Logger log = Logger.getLogger("X25519KeyExchange");

	final private String algorithm = "X25519";

	final private String provider = "BC";

	@Override
	public String getSharedSecret(PrivateKey originPrivatekey, PublicKey remotePublicKey)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
		KeyAgreement x25519KeyAgreement = KeyAgreement.getInstance(algorithm, provider);
		x25519KeyAgreement.init(originPrivatekey);
		x25519KeyAgreement.doPhase(remotePublicKey, true);
		final byte[] secretKey = x25519KeyAgreement.generateSecret();
		log.log(Level.FINE, "Created the secret key");
		return Base64.getEncoder().encodeToString(secretKey);
	}
	
	@Override
	public String getNonce() {
		String randonUUID = UUID.randomUUID().toString();
		return Base64.getEncoder().encodeToString(randonUUID.getBytes());
	}

}