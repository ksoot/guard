package com.ak.guard.confidentiality.keys;

import static com.ak.guard.common.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO;
import static com.ak.guard.common.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE;
import static com.ak.guard.common.GuardConstants.DH_PUBLIC_KEY_BITS;
import static com.ak.guard.common.GuardConstants.JCA_PROVIDER;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

public class EC25519ConfidentialKeys implements ConfidentialKeys {

	private static Logger log = Logger.getLogger("EC25519ConfidentialKeys");

	@Override
	public AlgorithmParameterSpec DHParamasAlgo()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
		log.log(Level.INFO, "Creating DHParams for Algo : " + ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO);
		AlgorithmParameters ecAlgoParams = AlgorithmParameters.getInstance(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO,
				JCA_PROVIDER);
		X9ECParameters ecP = CustomNamedCurves.getByName(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE);
		AlgorithmParameterSpec ecAlgoParamsSpec = EC5Util.convertToSpec(ecP);
		ecAlgoParams.init(ecAlgoParamsSpec);
		log.log(Level.INFO, "Successfully created DHParams for Algo : " + ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO);
		return ecAlgoParams.getParameterSpec(ECParameterSpec.class);
	}

	@Override
	public KeyPair GenerateDHKeyPair(AlgorithmParameterSpec ecAlgoParamsSpec) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
		log.log(Level.INFO, "Generating DH key pair using Algo : " + ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO);
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO, JCA_PROVIDER);
		kpg.initialize(DH_PUBLIC_KEY_BITS);
		kpg.initialize(ecAlgoParamsSpec);
		final KeyPair kp = kpg.genKeyPair();
		log.log(Level.INFO, "Successfully generated DH key pair using Algo : " + ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO);
		return kp;
	}

}
