package com.ak.guard;

import static com.ak.guard.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO;
import static com.ak.guard.GuardConstants.JCA_PROVIDER;
import static com.ak.guard.GuardConstants.RANDOM_NONCE_ALGO;
import static com.ak.guard.GuardConstants.RANDOM_NONCE_BITS;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

import java.security.DrbgParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.UUID;

public class GuardSingletons {

	private static KeyPairGenerator kpg;
	private static SecureRandom secureRandom256Strength;
	private static SecureRandom secureRandomDefaultStrength;
	private static KeyFactory keyFactory;
	
	public static KeyFactory keyFactory() throws NoSuchProviderException, NoSuchAlgorithmException {
		if (keyFactory == null) {
			keyFactory = KeyFactory.getInstance(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO, JCA_PROVIDER);
		}
		return keyFactory;
	}
	
	public static KeyPair GenerateDHKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
		if (kpg == null) {
			kpg = KeyPairGenerator.getInstance("algorithm", "provider");
		}
		return kpg.genKeyPair();
	}

	public static SecureRandom secureRandom256Strength() throws NoSuchAlgorithmException, NoSuchProviderException {
		if (secureRandom256Strength == null) {
			String initialSeed = UUID.randomUUID().toString();
			try {
				DrbgParameters.Instantiation params = DrbgParameters.instantiation(RANDOM_NONCE_BITS, PR_AND_RESEED,
						initialSeed.getBytes());
				secureRandom256Strength = SecureRandom.getInstance(RANDOM_NONCE_ALGO, params);
				secureRandom256Strength.setSeed(initialSeed.getBytes());
			} catch (NoSuchAlgorithmException e) {
				System.out.println("DRBG algorithm for generating CSPRNG is not supported");
			}

		}
		return secureRandom256Strength;
	}

	public static SecureRandom secureRandomDefaultStrength() throws NoSuchAlgorithmException, NoSuchProviderException {
		if (secureRandomDefaultStrength == null) {
			String initialSeed = UUID.randomUUID().toString();
			try {
				DrbgParameters.Instantiation params = DrbgParameters.instantiation(-1, PR_AND_RESEED,
						initialSeed.getBytes());
				secureRandomDefaultStrength = SecureRandom.getInstance(RANDOM_NONCE_ALGO, params, JCA_PROVIDER);
				secureRandomDefaultStrength.setSeed(initialSeed.getBytes());
			} catch (NoSuchAlgorithmException e) {
				System.out.println("DRBG algorithm for generating CSPRNG is not supported");
			}

		}
		return secureRandomDefaultStrength;
	}

	public static void randomNoPR256(boolean isPR, byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException {
		if (isPR == true) {
			secureRandom256Strength().nextBytes(input, DrbgParameters.nextBytes(-1, true, null));
		} else {
			secureRandom256Strength().nextBytes(input);
		}
	}

	public static byte[] randomNo256(byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException {
		secureRandom256Strength().nextBytes(input);
		return input;
	}

	public static byte[] randomNoDefault(byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException {
		secureRandomDefaultStrength().nextBytes(input);
		return input;
	}
}
