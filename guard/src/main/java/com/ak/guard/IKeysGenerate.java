package com.ak.guard;


import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import com.ak.guard.model.SerializedKeyPair;

import guard.KeyType;


public interface IKeysGenerate {

	public SerializedKeyPair getKeyPair()
			throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException;

	public String getPEMEncoded(Key key, KeyType type) throws IOException;

	public Key getPEMDecoded(final String pemEncodedKey, KeyType type)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException;

	default SecureRandom random() {
		return new SecureRandom();
	}
	
}
