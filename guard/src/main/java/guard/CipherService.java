package guard;

import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_ALGO;
import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_MODE;
import static com.ak.guard.GuardConstants.SYMMETRIC_CRYPTO_CIPHER_PAD;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import com.ak.guard.GuardConstants;

public class CipherService {

	Logger log = Logger.getLogger("CipherService");

	final String algorithm = "ECDH";
	String cipherAlgo = SYMMETRIC_CRYPTO_CIPHER_ALGO + "/" + SYMMETRIC_CRYPTO_CIPHER_MODE + "/"
			+ SYMMETRIC_CRYPTO_CIPHER_PAD;
	DHEService dheService = new DHEService();
	// 16 bytes is the size of the gcmtag
	final int gcmTagLength = 16;
	// Length of the IV
	final int ivLength = 12;
	// out of 32 byte salts the starting point for IV is 21. (32 - 21 = 12) with 0
	// index its 20
	final int saltIVOffset = 20;

	public String encrypt(PrivateKey ourPrivatekey, PublicKey remotePublicKey, String base64YourNonce,
			String base64RemoteNonce, String data)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		log.info("Attempt to encrypt");
		// derive the secret key
		String sharedSecret = dheService.getSharedSecret(ourPrivatekey, remotePublicKey);
		// Xor the nonce
		byte[] xoredNonce = xor(Base64.getDecoder().decode(base64YourNonce),
				Base64.getDecoder().decode(base64RemoteNonce));
		// create a session key with the derived secret
		String key = getSessionKey(Base64.getDecoder().decode(sharedSecret), xoredNonce);
		// Crease the cipher instance with the neessary encryption algorithm
		Cipher cipher = Cipher.getInstance(cipherAlgo, GuardConstants.JCA_PROVIDER);
		// Create the spec with the given session key
		SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
		byte[] iv = new byte[12];
		// Copy only the last 12 bytes
		System.arraycopy(xoredNonce, saltIVOffset, iv, 0, ivLength);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gcmTagLength * 8, iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
		byte[] cipherData = cipher.doFinal(data.getBytes());

		return Base64.getEncoder().encodeToString(cipherData);
	}

	public String decrypt(PrivateKey ourPrivatekey, PublicKey remotePublicKey, String base64YourNonce,
			String base64RemoteNonce, String base64EncodedData)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		log.info("Attempt to decrypt");
		String sharedSecret = dheService.getSharedSecret(ourPrivatekey, remotePublicKey);
		byte[] xoredNonce = xor(Base64.getDecoder().decode(base64YourNonce),
				Base64.getDecoder().decode(base64RemoteNonce));
		String key = getSessionKey(Base64.getDecoder().decode(sharedSecret), xoredNonce);
		Cipher cipher = Cipher.getInstance(cipherAlgo, GuardConstants.JCA_PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
		byte[] iv = new byte[12];
		System.arraycopy(xoredNonce, saltIVOffset, iv, 0, ivLength);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gcmTagLength * 8, iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
		byte[] cipherData = cipher.doFinal(Base64.getDecoder().decode(base64EncodedData));

		return Base64.getEncoder().encodeToString(cipherData);
	}

	public String getSessionKey(byte[] sharedSecret, byte[] xoredNonce) {

		byte[] salt = new byte[20];
		System.arraycopy(xoredNonce, 0, salt, 0, 20);
		HKDFParameters hkdf = new HKDFParameters(sharedSecret, salt, null);
		HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
		generator.init(hkdf);
		byte[] result = new byte[32];
		generator.generateBytes(result, 0, 32);
		return Base64.getEncoder().encodeToString(result);
	}

	private byte[] xor(byte[] a, byte[] key) {
		byte[] out = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			out[i] = (byte) (a[i] ^ key[i % key.length]);
		}
		return out;
	}

}