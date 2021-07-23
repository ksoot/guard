package com.ak.guard;

public final class GuardConstants {

	static final public String JCA_PROVIDER = "BC";

	static final public int RANDOM_NONCE_BITS = 256;
	static final public String RANDOM_NONCE_ALGO = "DRBG";

	static final public String KEY_EXCHANGE_ALGO = "DH";
	static final public String KEY_EXCHANGE_ENCODED_SPEC = "X509";

	static final public int DH_PUBLIC_KEY_BITS = 256;
	static final public int DH_PRIVATE_KEY_BITS = 128;
	static final public int DH_SHARED_KEY_BITS = 128;
	static final public int SESSION_KEY_BITS = 256;

	static final public String SYMMETRIC_CRYPTO_CIPHER_ALGO = "AES";
	static final public String SYMMETRIC_CRYPTO_CIPHER_MODE = "GCM";
	static final public String SYMMETRIC_CRYPTO_CIPHER_PAD = "NoPadding";
	static final public int SYMMETRIC_CRYPTO_CIPHER_BITS = 256;
	// the IV should be random
	static final public int SYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_IV_SIZE = 12;
	static final public String SYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_SALT = "Curve25519";

	static final public String ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO = "EC";
	static final public String ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE = "Curve25519";

	static final public String DIGEST_HASH_ALGO = "SHA-256";
	static final public String DIGEST_MAC_ALGO = "HMAC-SHA256";

	static final public String KEY_DERIVATION_FUNCTION = "HKDF";
	//// Quoted "Z" to indicate UTC, no 
	static final public String DATE_UTC_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
	static final public int KEY_EXPIRY = 24;
	static final public String TIME_ZONE = "UTC";

}
