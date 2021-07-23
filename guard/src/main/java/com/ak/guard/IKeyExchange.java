package com.ak.guard;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface IKeyExchange {
	
	 public String getSharedSecret(PrivateKey ourPrivatekey, PublicKey remotePublicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException;
	 
	 public String getNonce();
	 
}
