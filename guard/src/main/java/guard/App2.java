package guard;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ak.guard.GuardSingletons;
import com.ak.guard.model.CipherResponse;
import com.ak.guard.model.DecryptCipherParameter;
import com.ak.guard.model.EncryptCipherParameter;
import com.ak.guard.model.SecretKeySpec;
import com.ak.guard.model.SerializedKeyPair;
import com.ak.guard.model.SerializedSecretKey;
import com.fasterxml.jackson.core.JsonProcessingException;

public class App2 {

	public static void main(String[] args) throws JsonProcessingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());

		ECCController c = new ECCController();

		SerializedKeyPair serializedKeyPairFIU = c.generateKey();
		SerializedKeyPair serializedKeyPairFIP = c.generateKey();

		String privateKeyFIU = serializedKeyPairFIU.getPrivateKey();
		String publicKeyFIU = serializedKeyPairFIU.getKeyMaterial().getDhPublicKey().getKeyValue();

		String privateKeyFIP = serializedKeyPairFIP.getPrivateKey();
		String publicKeyFIP = serializedKeyPairFIP.getKeyMaterial().getDhPublicKey().getKeyValue();

		byte[] nonceFIU = new byte[64];
		byte[] nonceFIP = new byte[64];
		
		GuardSingletons.randomNoPR256(true, nonceFIU);
		GuardSingletons.randomNoPR256(true, nonceFIP);
		
		System.out.println("nonceFIU : " + nonceFIU);
		System.out.println("nonceFIP : " + nonceFIP);

		SecretKeySpec secretKeySpecFIU = new SecretKeySpec(publicKeyFIP, privateKeyFIU);
		SecretKeySpec secretKeySpecFIP = new SecretKeySpec(publicKeyFIU, privateKeyFIP);

		SerializedSecretKey serializedSecretKeyFIU = c.getSharedKey(secretKeySpecFIU);
		System.out.println("serializedSecretKeyFIU : " + serializedSecretKeyFIU.getKey());

		SerializedSecretKey serializedSecretKeyFIP = c.getSharedKey(secretKeySpecFIP);
		System.out.println("serializedSecretKeyFIP : " + serializedSecretKeyFIP.getKey());

		// At FIP end
		String plainText = "Hellojskfkjssakjfkdsfkjsahdkjsamsadmjsadm348732xni38434#%&9n!#)--udusd5/87";
		EncryptCipherParameter encryptCipherParameterFIP = new EncryptCipherParameter();
		encryptCipherParameterFIP.setOriginPrivateKey(privateKeyFIP);
		encryptCipherParameterFIP.setRemoteKeyMaterial(serializedKeyPairFIU.getKeyMaterial());
		encryptCipherParameterFIP.setBase64RemoteNonce(Base64.getEncoder().encodeToString(nonceFIU));
		encryptCipherParameterFIP.setBase64OriginNonce(Base64.getEncoder().encodeToString(nonceFIP));
		encryptCipherParameterFIP.setData(plainText);
		CipherResponse cipherResponse = c.encrypt(encryptCipherParameterFIP);
		// remoteNonce = UUID.randomUUID().toString();
		// System.out.println("remoteNonce 2 : "+remoteNonce);

		// At FIU end
		DecryptCipherParameter decryptCipherParameterFIU = new DecryptCipherParameter();
		decryptCipherParameterFIU.setOriginPrivateKey(privateKeyFIU);
		decryptCipherParameterFIU.setRemoteKeyMaterial(serializedKeyPairFIP.getKeyMaterial());
		decryptCipherParameterFIU.setBase64RemoteNonce(Base64.getEncoder().encodeToString(nonceFIP));
		decryptCipherParameterFIU.setBase64OriginNonce(Base64.getEncoder().encodeToString(nonceFIU));
		decryptCipherParameterFIU.setBase64Data(cipherResponse.getBase64Data());
		CipherResponse CipherResponse = c.decrypt(decryptCipherParameterFIU);
		String s = new String(Base64.getDecoder().decode(CipherResponse.getBase64Data()));
		System.out.println(plainText);
		System.out.println(s);
		boolean b = plainText.equals(s);
		System.out.println(b);

	}
}
