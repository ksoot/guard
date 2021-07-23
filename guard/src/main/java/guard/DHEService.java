package guard;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;

public class DHEService {

	Logger log = Logger.getLogger("X25519KeyExchange");

	final private String algorithm = "ECDH";

	final private String provider = "BC";

	public String getSharedSecret(PrivateKey originPrivatekey, PublicKey remotePublicKey)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
		KeyAgreement ecdhKeyAgreement = KeyAgreement.getInstance(algorithm, provider);
		ecdhKeyAgreement.init(originPrivatekey);
		ecdhKeyAgreement.doPhase(remotePublicKey, true);
		final byte[] secretKey = ecdhKeyAgreement.generateSecret();
		log.log(Level.FINE, "Created the secret key");
		return Base64.getEncoder().encodeToString(secretKey);
	}

}