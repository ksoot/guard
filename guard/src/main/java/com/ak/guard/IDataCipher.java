package com.ak.guard;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface IDataCipher {

	public String decrypt(PrivateKey ourPrivatekey, PublicKey remotePublicKey, String base64YourNonce,
			String base64RemoteNonce, String base64EncodedData)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;

	public String encrypt(PrivateKey ourPrivatekey, PublicKey remotePublicKey, String base64YourNonce,
			String base64RemoteNonce, String data)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;

}
