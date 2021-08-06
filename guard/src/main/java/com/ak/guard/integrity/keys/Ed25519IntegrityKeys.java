package com.ak.guard.integrity.keys;

import static com.ak.guard.common.GuardConstants.ECC_ALGO;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Ed25519IntegrityKeys implements IntegrityKeys {

	private static Logger log = Logger.getLogger("Ed25519IntegrityKeys");

	@Override
	public KeyPair generateEdAsymmetricKey() {
		log.log(Level.INFO, "Generating Digital Signature key pair using Algo : " + ECC_ALGO);
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(ECC_ALGO);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception: While initializing " + ECC_ALGO);
		}
		log.log(Level.INFO, "Successfully generated Digital Signature key pair using Algo : " + ECC_ALGO);
		return keyPairGenerator.generateKeyPair();
	}

	
}
