package com.ak.guard.confidentiality.keys;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyExchange   {

	
	public byte[] DHSharedKeyAlgo(final PublicKey publicKey, final PrivateKey privateKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException;
	
	public byte[] GenerateSessionKeyAlgo(final byte[] encodedSecretKey, final byte[] encodedOriginNonce, final byte[] encodedRemoteNonce)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException;
	

}
