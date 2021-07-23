package guard;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import com.ak.guard.X25519DataCipher;
import com.ak.guard.X25519KeyExchange;
import com.ak.guard.X25519KeysGenerate;
import com.ak.guard.model.CipherResponse;
import com.ak.guard.model.DecryptCipherParameter;
import com.ak.guard.model.EncryptCipherParameter;
import com.ak.guard.model.ErrorInfo;
import com.ak.guard.model.KeyMaterial;
import com.ak.guard.model.SecretKeySpec;
import com.ak.guard.model.SerializedKeyPair;
import com.ak.guard.model.SerializedSecretKey;


public class Controller {

	Logger log = Logger.getLogger("Controller");

	private X25519KeysGenerate x25519KeysGenerate = new X25519KeysGenerate();
	private X25519KeyExchange x25519KeyExchange = new X25519KeyExchange();
	private X25519DataCipher x25519DataCipher = new X25519DataCipher();

	// Generate a new ecc key pair
	public SerializedKeyPair generateKey() {
		try {
			log.info("Generate Key");
			return x25519KeysGenerate.getKeyPair();
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
				| IOException ex) {
			log.log(Level.SEVERE, "Unable to generateKey");
			final SerializedKeyPair errorKeyPair = new SerializedKeyPair("", new KeyMaterial());
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			errorKeyPair.setErrorInfo(error);
			return errorKeyPair;
		}

	}

	// "Generate the shared key for the given remote public key (other party in
	// X509encoded Spec) and our private key (our private key encoded in PKCS#8
	// format) ")
	public SerializedSecretKey getSharedKey(SecretKeySpec spec) {
		try {
			log.info("Generate Shared Secret");
			log.log(Level.FINE, "Get PrivateKey");
			final Key originPrivateKey = x25519KeysGenerate.getPEMDecoded(spec.getOriginPrivateKey(), KeyType.PRIVATE_KEY);
			log.log(Level.FINE, "Get PublicKey");
			final Key remoterPublicKey = x25519KeysGenerate.getPEMDecoded(spec.getRemotePublicKey(), KeyType.PUBLIC_KEY);
			log.log(Level.FINE, "Got the key decoded. Lets generate secret key");
			final String secretKey = x25519KeyExchange.getSharedSecret((PrivateKey) originPrivateKey,
					(PublicKey) remoterPublicKey);
			return new SerializedSecretKey(secretKey);
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | IOException
				| InvalidKeySpecException ex) {
			log.log(Level.SEVERE, "Error when deriving secret key");
			final SerializedSecretKey errorKeyPair = new SerializedSecretKey("");
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			errorKeyPair.setErrorInfo(error);
			return errorKeyPair;
		}

	}

	// "Encrypt the data for the given key material (other party in X509encoded
	// Spec) and our private key (our private key encoded in PKCS#8 format) , remote
	// nonce (base64) and local nonce (base64). Send the input data as a string.
	// Encryption assumes the given data is a string")
	public CipherResponse encrypt(EncryptCipherParameter encryptCipherParam) {
		try {
			log.info("Encrypt complete data");
			log.log(Level.FINE, "Get PrivateKey");
			final Key originPrivateKey = x25519KeysGenerate.getPEMDecoded(encryptCipherParam.getOriginPrivateKey(),
					KeyType.PRIVATE_KEY);
			log.log(Level.FINE, "Get PublicKey");
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no
			Date expiryDate;
			try {
				expiryDate = df.parse(encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
			} catch (ParseException ex) {
				throw new InvalidKeyException("Unable to parse date");
			}

			if (!expiryDate.after(new Date())) {
				throw new InvalidKeyException("Expired Key");
			}
			final Key remotePublicKey = x25519KeysGenerate.getPEMDecoded(
					encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue(), KeyType.PUBLIC_KEY);
			log.log(Level.FINE, "Initiate Encryption");
			String result = x25519DataCipher.encrypt((PrivateKey) originPrivateKey, (PublicKey) remotePublicKey,
					encryptCipherParam.getBase64OriginNonce(), encryptCipherParam.getBase64RemoteNonce(),
					encryptCipherParam.getData());
			log.log(Level.FINE, "Completed Encryption");
			return new CipherResponse(result, null);

		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException
				| NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException | IOException ex) {

			log.log(Level.SEVERE, "Error during encryption");
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			return new CipherResponse("", error);
		}

	}

	// "Decrypt the data for the given remote public key (other party in X509encoded
	// Spec) and our private key (our private key encoded in PKCS#8 format) , remote
	// nonce (base64) and local nonce (base64). The result is base64 encoded")
	public CipherResponse decrypt(final DecryptCipherParameter decryptCipherParam) {
		try {
			log.info("Decrypt complete data");
			log.log(Level.FINE, "Get PrivateKey");
			final Key originPrivateKey = x25519KeysGenerate.getPEMDecoded(decryptCipherParam.getOriginPrivateKey(),
					KeyType.PRIVATE_KEY);
			log.log(Level.FINE, "Get PublicKey");
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no
			Date expiryDate;
			try {
				expiryDate = df.parse("");
			} catch (ParseException ex) {
				throw new InvalidKeyException("Unable to parse date");
			}

			if (!expiryDate.after(new Date())) {
				throw new InvalidKeyException("Expired Key");
			}
			final Key remotePublicKey = x25519KeysGenerate.getPEMDecoded(
					"", KeyType.PUBLIC_KEY);
			log.log(Level.FINE, "Initiate Decryption");
			String result = x25519DataCipher.decrypt((PrivateKey) originPrivateKey, (PublicKey) remotePublicKey,
					decryptCipherParam.getBase64OriginNonce(), decryptCipherParam.getBase64RemoteNonce(),
					decryptCipherParam.getBase64Data());
			log.log(Level.FINE, "Completed Decryption");
			return new CipherResponse(result, null);

		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException
				| NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException | IOException ex) {

			log.log(Level.SEVERE, "Error during decryption");
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			return new CipherResponse("", error);
		}

	}
	
	
}

