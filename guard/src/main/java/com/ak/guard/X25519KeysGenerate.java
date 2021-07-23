package com.ak.guard;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import com.ak.guard.model.DHPublicKey;
import com.ak.guard.model.KeyMaterial;
import com.ak.guard.model.SerializedKeyPair;

import guard.KeyType;

public class X25519KeysGenerate implements IKeysGenerate{
	
	
	String algorithm = "X25519", keyDerivationAlgorithm = "X25519";
	String provider = "BC";
	int keyExpiry = 30;
	
	
	private KeyPair getKeyPairGenerator() throws NoSuchProviderException, NoSuchAlgorithmException {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
		return kpg.genKeyPair();
	}

	@Override
	public SerializedKeyPair getKeyPair()
			throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {

		final KeyPair keyPair = this.getKeyPairGenerator();
		final String privateKey = this.getPEMEncoded(keyPair.getPrivate(), KeyType.PRIVATE_KEY);
		final String publicKey = this.getPEMEncoded(keyPair.getPublic(), KeyType.PUBLIC_KEY);
		Date date = new Date();
		Calendar cl = Calendar.getInstance();
		cl.setTime(date);
		cl.add(Calendar.HOUR, keyExpiry);
		TimeZone tz = TimeZone.getTimeZone("UTC");
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no timezone
																				// offset
		df.setTimeZone(tz);
		String expiryAsISO = df.format(cl.getTime());
		final DHPublicKey dhPublicKey = new DHPublicKey(expiryAsISO, "", publicKey);
		final KeyMaterial keyMaterial = new KeyMaterial(keyDerivationAlgorithm, "", "", dhPublicKey);
		final SerializedKeyPair serializedKeyPair = new SerializedKeyPair(privateKey, keyMaterial);
		return serializedKeyPair;
	}

	@Override
	public String getPEMEncoded(Key key, KeyType type) throws IOException {

		String keyDescription = type.equals(KeyType.PRIVATE_KEY) ? "PRIVATE KEY" : "PUBLIC KEY";
		StringWriter writer = new StringWriter();
		PemObject pemObject = new PemObject(keyDescription, key.getEncoded());
		PemWriter pemWriter = new PemWriter(writer);
		pemWriter.writeObject(pemObject);
		pemWriter.flush();
		pemWriter.close();
		return writer.toString();
	}

	@Override
	public Key getPEMDecoded(final String pemEncodedKey, KeyType type)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
		StringReader reader = new StringReader(pemEncodedKey);
		PemReader pemReader = new PemReader(reader);
		if (type.equals(KeyType.PRIVATE_KEY)) {
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
			return KeyFactory.getInstance(algorithm, provider).generatePrivate(spec);
		} else {
			KeySpec keySpec = new X509EncodedKeySpec(pemReader.readPemObject().getContent());
			return KeyFactory.getInstance(algorithm, provider).generatePublic(keySpec);
		}
	}

	@Override
	public SecureRandom random() {
		SecureRandom random = new SecureRandom();
		return random;
	}


}
