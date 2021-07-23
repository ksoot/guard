package guard;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ak.guard.X25519KeyExchange;
import com.ak.guard.model.CipherResponse;
import com.ak.guard.model.DecryptCipherParameter;
import com.ak.guard.model.SecretKeySpec;
import com.ak.guard.model.SerializedKeyPair;
import com.ak.guard.model.SerializedSecretKey;
import com.fasterxml.jackson.core.JsonProcessingException;

public class App {

	public static void main(String[] args) throws JsonProcessingException {
		Security.addProvider(new BouncyCastleProvider());
		X25519KeyExchange x25519KeyExchange = new X25519KeyExchange();

		

		ECCController c = new ECCController();
		
		 SecureRandom sr = new SecureRandom();
	     byte ourNonce[] = new byte[32];
	     sr.nextBytes(ourNonce);
	     Base64.getEncoder().encodeToString(ourNonce);
	     

		SerializedKeyPair serializedKeyPairFIU = c.generateKey();
		//SerializedKeyPair serializedKeyPairFIP = c.generateKey();
		System.out.println(serializedKeyPairFIU.getKeyMaterial().toString());

		String privateKeyFIU = serializedKeyPairFIU.getPrivateKey();
		String publicKeyFIU = serializedKeyPairFIU.getKeyMaterial().getDhPublicKey().getKeyValue();

		//String privateKeyFIP = serializedKeyPairFIP.getPrivateKey();
		//String publicKeyFIP = serializedKeyPairFIP.getKeyMaterial().getDhPublicKey().getKeyValue();

		String nonceFIU = Base64.getEncoder().encodeToString(ourNonce);
		//String nonceFIP = x25519KeyExchange.getNonce();

		System.out.println("nonceFIU : " + nonceFIU);
	//	System.out.println("nonceFIP : " + nonceFIP);

		SecretKeySpec secretKeySpecFIU = new SecretKeySpec("", privateKeyFIU);
	//	SecretKeySpec secretKeySpecFIP = new SecretKeySpec(publicKeyFIU, privateKeyFIP);

		SerializedSecretKey serializedSecretKeyFIU = c.getSharedKey(secretKeySpecFIU);
		System.out.println("serializedSecretKeyFIU : " + serializedSecretKeyFIU.getKey());

	//	SerializedSecretKey serializedSecretKeyFIP = c.getSharedKey(secretKeySpecFIP);
	//	System.out.println("serializedSecretKeyFIP : " + serializedSecretKeyFIP.getKey());

	/*
	 * // At FIP end EncryptCipherParameter encryptCipherParameterFIP = new
	 * EncryptCipherParameter();
	 * encryptCipherParameterFIP.setOriginPrivateKey(privateKeyFIP);
	 * encryptCipherParameterFIP.setRemoteKeyMaterial(serializedKeyPairFIU.
	 * getKeyMaterial());
	 * encryptCipherParameterFIP.setBase64RemoteNonce(Base64.getEncoder().
	 * encodeToString(nonceFIU.getBytes()));
	 * encryptCipherParameterFIP.setBase64OriginNonce(Base64.getEncoder().
	 * encodeToString(nonceFIP.getBytes())); encryptCipherParameterFIP.setData(
	 * "Hellojskfkjssakjfkdsfkjsahdkjsamsadmjsadm348732xni38434#%&9n!#)--udusd5/87")
	 * ; CipherResponse cipherResponse = c.encrypt(encryptCipherParameterFIP);
	 */
		// remoteNonce = UUID.randomUUID().toString();
		// System.out.println("remoteNonce 2 : "+remoteNonce);

		// At FIU end
		DecryptCipherParameter decryptCipherParameterFIU = new DecryptCipherParameter();
		decryptCipherParameterFIU.setOriginPrivateKey(privateKeyFIU);
		decryptCipherParameterFIU.setRemoteKeyMaterial(null);
		decryptCipherParameterFIU.setBase64RemoteNonce("");
		decryptCipherParameterFIU.setBase64OriginNonce(Base64.getEncoder().encodeToString(nonceFIU.getBytes()));
		decryptCipherParameterFIU.setBase64Data("");
		CipherResponse CipherResponse = c.decrypt(decryptCipherParameterFIU);
		String s = new String(Base64.getDecoder().decode(CipherResponse.getBase64Data()));
		System.out.println(s);

	}
}
