package guard;

import static com.ak.guard.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO;
import static com.ak.guard.GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE;
import static com.ak.guard.GuardConstants.DH_PUBLIC_KEY_BITS;
import static com.ak.guard.GuardConstants.JCA_PROVIDER;
import static com.ak.guard.GuardConstants.KEY_EXCHANGE_ALGO;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import com.ak.guard.GuardConstants;
import com.ak.guard.GuardSingletons;
import com.ak.guard.GuardUtils;
import com.ak.guard.model.DHPublicKey;
import com.ak.guard.model.KeyMaterial;
import com.ak.guard.model.SerializedKeyPair;

public class ECCService {
	Logger log = Logger.getLogger("ECCService");
	
	private String keyDerivationAlgorithm = ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO+KEY_EXCHANGE_ALGO;

	public SerializedKeyPair getKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidParameterSpecException {

		final KeyPair kp = GuardUtils.generateKeyPair();
		final String privateKey = GuardUtils.transformKeyToSpec(kp.getPrivate());
		final String publicKey = GuardUtils.transformKeyToSpec(kp.getPublic());
		String expiryAsISO = GuardUtils.getDateInISOText();
		final DHPublicKey dhPublicKey = new DHPublicKey(expiryAsISO, "", publicKey);
		final KeyMaterial keyMaterial = new KeyMaterial(keyDerivationAlgorithm, GuardConstants.ASYMMETRIC_CRYPTO_KEY_GENERAION_ALGO_CURVE, "", dhPublicKey);
		final SerializedKeyPair serializedKeyPair = new SerializedKeyPair(privateKey, keyMaterial);
		return serializedKeyPair;
	}

}
