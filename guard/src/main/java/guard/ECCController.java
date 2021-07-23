package guard;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.ak.guard.GuardUtils;
import com.ak.guard.model.CipherResponse;
import com.ak.guard.model.DecryptCipherParameter;
import com.ak.guard.model.EncryptCipherParameter;
import com.ak.guard.model.ErrorInfo;
import com.ak.guard.model.KeyMaterial;
import com.ak.guard.model.SecretKeySpec;
import com.ak.guard.model.SerializedKeyPair;
import com.ak.guard.model.SerializedSecretKey;

public class ECCController {

	Logger log = Logger.getLogger("ECCController");

	private ECCService eccService = new ECCService();

	private DHEService dheService = new DHEService();

	private CipherService cipherService = new CipherService();

	public SerializedKeyPair generateKey() throws InvalidKeySpecException {
		try {
			log.info("Generate Key");
			return eccService.getKeyPair();
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidParameterSpecException ex) {
			log.log(Level.SEVERE, "Unable to generateKey");
			final SerializedKeyPair errorKeyPair = new SerializedKeyPair("", new KeyMaterial());
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			errorKeyPair.setErrorInfo(error);
			return errorKeyPair;
		}
	}

	public SerializedSecretKey getSharedKey(final SecretKeySpec spec) {
		try {
			log.info("Generate Shared Secret");
			log.log(Level.FINE, "Get PrivateKey");
			final Key ourPrivateKey = GuardUtils.transformEncodedSpecToKey(spec.getOriginPrivateKey());
			log.log(Level.FINE, "Get PublicKey");
			final Key ourPublicKey = GuardUtils.transformEncodedSpecToKey(spec.getRemotePublicKey());
			log.log(Level.FINE, "Got the key decoded. Lets generate secret key");
			final String secretKey = dheService.getSharedSecret((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey);
			return new SerializedSecretKey(secretKey);
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
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

	public CipherResponse encrypt(final EncryptCipherParameter encryptCipherParam) {
		try {
			log.info("Encrypt complete data");
			log.log(Level.FINE, "Get PrivateKey");
			final Key ourPrivateKey = GuardUtils.transformEncodedSpecToKey(encryptCipherParam.getOriginPrivateKey());
			log.log(Level.FINE, "Get PublicKey");
			Date expiryDate = GuardUtils.parseDateToUTC(encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
			if (!expiryDate.after(new Date())) {
				throw new InvalidKeyException("Expired Key");
			}
			final Key ourPublicKey = GuardUtils.transformEncodedSpecToKey(encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue());
			log.log(Level.FINE, "Initiate Encryption");
			String result = cipherService.encrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey,
					encryptCipherParam.getBase64OriginNonce(), encryptCipherParam.getBase64RemoteNonce(),
					encryptCipherParam.getData());
			log.log(Level.FINE, "Completed Encryption");
			return new CipherResponse(result, null);

		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException
				| NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException ex) {

			log.log(Level.SEVERE, "Error during encryption");
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			return new CipherResponse("", error);
		}

	}

	public CipherResponse decrypt(final DecryptCipherParameter decryptCipherParam) {
		try {
			log.info("Decrypt complete data");
			log.log(Level.FINE, "Get PrivateKey");
			final Key ourPrivateKey = GuardUtils.transformEncodedSpecToKey(decryptCipherParam.getOriginPrivateKey());
			log.log(Level.FINE, "Get PublicKey");
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no
			Date expiryDate = GuardUtils.parseDateToUTC(decryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
			if (!expiryDate.after(new Date())) {
				throw new InvalidKeyException("Expired Key");
			}
			final Key ourPublicKey = GuardUtils.transformEncodedSpecToKey(decryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue());
			log.log(Level.FINE, "Initiate Decryption");
			String result = cipherService.decrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey,
					decryptCipherParam.getBase64OriginNonce(), decryptCipherParam.getBase64RemoteNonce(),
					decryptCipherParam.getBase64Data());
			log.log(Level.FINE, "Completed Decryption");
			return new CipherResponse(result, null);

		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException
				| NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException ex) {

			log.log(Level.SEVERE, "Error during decryption");
			final ErrorInfo error = new ErrorInfo();
			error.setErrorCode(ex.getClass().getName());
			error.setErrorMessage(ex.getMessage());
			return new CipherResponse("", error);
		}

	}

}