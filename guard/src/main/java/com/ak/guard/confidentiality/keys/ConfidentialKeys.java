package com.ak.guard.confidentiality.keys;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public interface ConfidentialKeys {

	public AlgorithmParameterSpec DHParamasAlgo()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException;

	public KeyPair GenerateDHKeyPair(AlgorithmParameterSpec ecAlgoParamsSpec) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException, InvalidParameterSpecException;

}
