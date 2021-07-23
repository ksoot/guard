package com.ak.guard;

import static com.ak.guard.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO;
import static com.ak.guard.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE;
import static com.ak.guard.GuardConstants.DATE_UTC_FORMAT;
import static com.ak.guard.GuardConstants.DH_PUBLIC_KEY_BITS;
import static com.ak.guard.GuardConstants.DIGEST_HASH_ALGO;
import static com.ak.guard.GuardConstants.DIGEST_MAC_ALGO;
import static com.ak.guard.GuardConstants.JCA_PROVIDER;
import static com.ak.guard.GuardConstants.KEY_EXPIRY;
import static com.ak.guard.GuardConstants.RANDOM_NONCE_ALGO;
import static com.ak.guard.GuardConstants.RANDOM_NONCE_BITS;
import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_ALGO;
import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_MODE;
import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_PAD;
import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_IV_SIZE;
import static com.ak.guard.GuardConstants.TIME_ZONE;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

import java.math.BigInteger;
import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import com.ak.guard.model.DHParam;

public class GuardUtils {

	private static Logger log = Logger.getLogger("GuardUtils");
	
	public DHParam DHParamasAlgo(final ECParameterSpec spec) {
		BigInteger p = null;
		if (spec.getCurve().getField() instanceof ECFieldFp) {
			p = ((ECFieldFp) spec.getCurve().getField()).getP();
		}
		return new DHParam(p, spec.getCurve().getB(), spec.getCurve().getA(), spec.getGenerator(), spec.getOrder(),
				spec.getCofactor());
	}

	public SecureRandom secureRandom(byte[] intialSeed) throws NoSuchAlgorithmException, NoSuchProviderException {
		SecureRandom randomNonce = null;
		try {
			DrbgParameters.Instantiation params = DrbgParameters.instantiation(RANDOM_NONCE_BITS, PR_AND_RESEED,
					intialSeed == null ? UUID.randomUUID().toString().getBytes() : intialSeed);
			randomNonce = SecureRandom.getInstance(RANDOM_NONCE_ALGO, params, JCA_PROVIDER);

		} catch (NoSuchAlgorithmException e) {
			System.out.println("DRBG algorithm for generating CSPRNG is not supported");
		}
		randomNonce.setSeed(intialSeed);
		return randomNonce;
	}

	public String generateEncodedIV() throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] iv = new byte[SYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_IV_SIZE];
		SecureRandom secureRandom = this.secureRandom(UUID.randomUUID().toString().getBytes());
		secureRandom.nextBytes(iv);
		return Base64.getEncoder().encodeToString(iv);
	}

	public Cipher encryptDecryptSymetric(int mode, Key key, AlgorithmParameterSpec params)
			throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		SecretKey myKey = null;
		byte[] myAAD = null;
		byte[] plainText = null;
		int myTLen = 0;
		byte[] myIv = this.generateEncodedIV().getBytes();

		String cipherAlgo = SYMMETRIC_CRYPTO_CIPHER_ALGO + "/" + SYMMETRIC_CRYPTO_CIPHER_MODE + "/"
				+ SYMMETRIC_CRYPTO_CIPHER_PAD;
		GCMParameterSpec myParams = new GCMParameterSpec(myTLen, myIv);
		Cipher cipher = Cipher.getInstance(cipherAlgo, JCA_PROVIDER);
		cipher.init(mode, myKey, myParams, this.secureRandom(null));
		return cipher;
	}

	public MessageDigest hash() throws NoSuchAlgorithmException, NoSuchProviderException {
		MessageDigest hash = MessageDigest.getInstance(DIGEST_HASH_ALGO, JCA_PROVIDER);
		return hash;
	}

	public Mac hmac(Key key, AlgorithmParameterSpec params) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		Mac hmac = Mac.getInstance(DIGEST_MAC_ALGO, JCA_PROVIDER);
		hmac.init(key, params);
		return hmac;
	}

	public static KeySpec getEncodedKeySpec(boolean isPrivateKey, String encodedKeySpec) {
		final byte[] decodedKeySpec = Base64.getDecoder().decode(encodedKeySpec);
		if (isPrivateKey == true) {
			log.log(Level.FINE, "Its a private key");
			EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKeySpec);
			log.log(Level.FINE, "PKCS8 decoded");
			return keySpec;
		} else if (isPrivateKey == false) {
			// log.log(Level.FINE, "Its a public key");
			EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKeySpec);
			// log.log(Level.FINE, "X509 decoded");
			return keySpec;
		} else {
			throw new RuntimeException("Invalid key type : ");
		}
	}

	// used at the time of building keys objects from key specs. Key specs hold
	// string representation of keys which is either supplied as rest api response
	// or retreived from store
	// object -> key spec or key material
	// key spec or key material -> object
	public static Key getKeyFromKeySpecFromFactory(KeySpec keySpec)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

		if (keySpec instanceof PKCS8EncodedKeySpec) {
			return GuardSingletons.keyFactory().generatePrivate(keySpec);
		} else if (keySpec instanceof X509EncodedKeySpec) {
			return GuardSingletons.keyFactory().generatePublic(keySpec);
		} else {
			throw new RuntimeException("Invalid key type : ");
		}
	}

	public String getSharedSecret(KeySpec originPrivatekey, KeySpec remotePublicKey)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO, JCA_PROVIDER);
		// SecretKeySpec d = new SecretKeySpec(null,
		// ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO)
		SecretKey secretKey = factory.generateSecret(remotePublicKey);
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());
	}

	public static Date parseDateToUTC(String expiryAsISO) {
		DateFormat df = new SimpleDateFormat(DATE_UTC_FORMAT);
		Date expiryDate;
		try {
			expiryDate = df.parse(expiryAsISO);
		} catch (Exception ex) {
			throw new RuntimeException("Unable to parse date : " + expiryAsISO, ex);
		}
		return expiryDate;
	}

	public static String getDateInISOText() {
		String expiryAsISO = null;
		Calendar cl = Calendar.getInstance();
		cl.setTime(new Date());
		cl.add(Calendar.HOUR, KEY_EXPIRY);
		TimeZone tz = TimeZone.getTimeZone(TIME_ZONE);
		cl.setTimeZone(tz);
		DateFormat df = new SimpleDateFormat(DATE_UTC_FORMAT);
		try {
			expiryAsISO = df.format(cl.getTime());
		} catch (Exception ex) {
			throw new RuntimeException("Unable to format date : " + expiryAsISO, ex);
		}
		return expiryAsISO;
	}

	public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidParameterSpecException {
		KeyPairGenerator kpg;
		kpg = KeyPairGenerator.getInstance(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO, JCA_PROVIDER);
		X9ECParameters ecP = CustomNamedCurves.getByName(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE);
		ECParameterSpec ecSpec = EC5Util.convertToSpec(ecP);
		kpg.initialize(DH_PUBLIC_KEY_BITS);
		kpg.initialize(ecSpec);
		final KeyPair kp = kpg.genKeyPair();
		log.info("Key pair generated " + kp.getPublic().getAlgorithm());
		return kp;
	}

	public static String transformKeyToSpec(final Key key) {
		String keyType = null;
		EncodedKeySpec encodedKeySpec = null;
		final StringBuilder sb = new StringBuilder();
		if (key instanceof PrivateKey) {
			keyType = "PRIVATE";
			encodedKeySpec = new PKCS8EncodedKeySpec(key.getEncoded());
		} else if (key instanceof PublicKey) {
			keyType = "PUBLIC";
			encodedKeySpec = new X509EncodedKeySpec(key.getEncoded());
		}

		sb.append("-----BEGIN " + keyType + " KEY-----");
		sb.append(new String(Base64.getEncoder().encode(encodedKeySpec.getEncoded())));
		sb.append("-----END " + keyType + " KEY-----");
		return sb.toString();
	}

	public static Key transformEncodedSpecToKey(final String encodedKeySpec)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		boolean isPrivateKey = false;
		String keyType = null;
		String encodedKey = "";
		if (encodedKeySpec.startsWith("-----BEGIN PRIVATE KEY-----")) {
			isPrivateKey = true; keyType = "PRIVATE";
			encodedKey = encodedKeySpec.replaceAll("-----BEGIN "+keyType+" KEY-----", "")
					.replaceAll("-----END "+keyType+" KEY-----", "");
		} else {
			keyType = "PUBLIC";
			encodedKey = encodedKeySpec.replaceAll("-----BEGIN "+keyType+" KEY-----", "")
					.replaceAll("-----END "+keyType+" KEY-----", "");
		}
		KeySpec keySpec = getEncodedKeySpec(isPrivateKey, encodedKey);
		return getKeyFromKeySpecFromFactory(keySpec);

	}

}
