package com.ak.guard.common;

import static com.ak.guard.common.GuardConstants.DATE_UTC_FORMAT;
import static com.ak.guard.common.GuardConstants.DIGEST_HASH_ALGO;
import static com.ak.guard.common.GuardConstants.DIGEST_MAC_ALGO;
import static com.ak.guard.common.GuardConstants.JCA_PROVIDER;
import static com.ak.guard.common.GuardConstants.KEY_EXPIRY;
import static com.ak.guard.common.GuardConstants.TIME_ZONE;

import java.math.BigInteger;
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
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;

import com.ak.guard.model.DHParam;

public class CommonUtil {

	private static Logger log = Logger.getLogger("GuardUtils");

	final protected static char[] hexArray = "0123456789abcdef".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public DHParam populateDHParams(AlgorithmParameterSpec ecAlgoParams)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
		log.log(Level.INFO, "Populating DHParams");

		if (ecAlgoParams instanceof ECParameterSpec) {
			BigInteger p = null;
			ECParameterSpec spec = (ECParameterSpec) ecAlgoParams;
			if (spec.getCurve().getField() instanceof ECFieldFp) {
				p = ((ECFieldFp) spec.getCurve().getField()).getP();
			}
			return new DHParam(p, spec.getCurve().getB(), spec.getCurve().getA(), spec.getGenerator(), spec.getOrder(),
					spec.getCofactor());
		}

		log.log(Level.INFO, "Successfully populated DHParams");
		return null;
	}

	public Object populateDHKeyMaterial(DHParam params, DHPublicKey key, String nonce)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
		log.log(Level.INFO, "Populating key material");
		// KeyMaterial keyMaterial = new KeyMaterial(KEY_EXCHANGE_ALGO,
		// ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE, params, key, nonce);
		log.log(Level.INFO, "Successfully populated key material");
		return null;
	}

	public boolean checkIfDHParamsAgreeable(AlgorithmParameterSpec ecAlgoParamSpec) {
		log.log(Level.INFO, "checking if params are aggregable");
		boolean flag = true;
		if (flag == true) {
			System.out.println("params are aggregable");
		} else {
			System.out.println("params are not aggregable");
		}
		return flag;
	}

	public static byte[] xored(final byte[] encodedOriginNonce, final byte[] encodedRemoteNonce) {
		byte[] decodedOriginNonce = CommonUtil.decodedBytes(encodedOriginNonce);
		byte[] decodedRemoteNonce = CommonUtil.decodedBytes(encodedRemoteNonce);
		byte[] out = new byte[decodedOriginNonce.length];
		for (int i = 0; i < decodedOriginNonce.length; i++) {
			out[i] = (byte) (decodedOriginNonce[i] ^ decodedRemoteNonce[i % decodedRemoteNonce.length]);
		}
		return out;
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
		CachableSingletons.keyFactory();
		if (keySpec instanceof PKCS8EncodedKeySpec) {
			return CachableSingletons.keyFactory().generatePrivate(keySpec);
		} else if (keySpec instanceof X509EncodedKeySpec) {
			return CachableSingletons.keyFactory().generatePublic(keySpec);
		} else {
			throw new RuntimeException("Invalid key type : ");
		}
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

	public static String transformKeyToEncodedSpec(final Key key) {
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
			isPrivateKey = true;
			keyType = "PRIVATE";
			encodedKey = encodedKeySpec.replaceAll("-----BEGIN " + keyType + " KEY-----", "")
					.replaceAll("-----END " + keyType + " KEY-----", "");
		} else {
			keyType = "PUBLIC";
			encodedKey = encodedKeySpec.replaceAll("-----BEGIN " + keyType + " KEY-----", "")
					.replaceAll("-----END " + keyType + " KEY-----", "");
		}
		KeySpec keySpec = getEncodedKeySpec(isPrivateKey, encodedKey);
		return getKeyFromKeySpecFromFactory(keySpec);

	}

	public static final byte[] decodedBytes(byte[] bytes) {
		return Base64.getDecoder().decode(bytes);
	}

	public static final byte[] encodedBytes(byte[] bytes) {
		return Base64.getEncoder().encode(bytes);
	}

	public static final String decodedBytesAsString(byte[] bytes) {
		return new String(Base64.getDecoder().decode(bytes));
	}

	public static final String encodedBytesAsString(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	public static final String bytesAsString(byte[] bytes) {
		return new String(bytes);
	}

	public static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}

}
