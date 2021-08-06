package com.ak.guard.common;

import static com.ak.guard.common.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO;
import static com.ak.guard.common.GuardConstants.JCA_PROVIDER;
import static com.ak.guard.common.GuardConstants.RANDOM_NONCE_ALGO;
import static com.ak.guard.common.GuardConstants.RANDOM_NONCE_BITS;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

import java.security.DrbgParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.util.UUID;

public class CachableSingletons {

	private static KeyPairGenerator kpg;
	private static SecureRandom drbg256Random;
	private static SecureRandom drbgDefaultRandom;
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

	public static SecureRandom drbg256Random() throws NoSuchAlgorithmException, NoSuchProviderException {
		if (drbg256Random == null) {
			String initialSeed = UUID.randomUUID().toString();
			try {
				DrbgParameters.Instantiation params = DrbgParameters.instantiation(RANDOM_NONCE_BITS, PR_AND_RESEED,
						initialSeed.getBytes());
				drbg256Random = SecureRandom.getInstance(RANDOM_NONCE_ALGO, params);
			} catch (NoSuchAlgorithmException e) {
				System.out.println("DRBG algorithm for generating CSPRNG is not supported");
			}

		}
		return drbg256Random;
	}

	public static SecureRandom drbgDefaultRandom() throws NoSuchAlgorithmException, NoSuchProviderException {
		if (drbgDefaultRandom == null) {
			try {
				drbgDefaultRandom = SecureRandom.getInstance(RANDOM_NONCE_ALGO, JCA_PROVIDER);
			} catch (NoSuchAlgorithmException e) {
				System.out.println("DRBG algorithm for generating CSPRNG is not supported");
			}

		}
		return drbgDefaultRandom;
	}

	public static byte[] randomPR256() throws NoSuchAlgorithmException, NoSuchProviderException {
			final byte[] input = new byte[RANDOM_NONCE_BITS];
			drbg256Random().nextBytes(input, DrbgParameters.nextBytes(RANDOM_NONCE_BITS, true, null));
			return CommonUtil.encodedBytes(input);
	}

	public static byte[] randomNo256() throws NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] input = new byte[RANDOM_NONCE_BITS];
		drbg256Random().nextBytes(input);
		return CommonUtil.encodedBytes(input);
	}

	public static byte[] randomNoDefault() throws NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] input = new byte[RANDOM_NONCE_BITS];
		drbgDefaultRandom().nextBytes(input);
		return CommonUtil.encodedBytes(input);
	}
}
