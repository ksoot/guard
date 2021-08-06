package com.ak.guard;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.ak.guard.common.CachableSingletons;
import com.ak.guard.common.CommonUtil;
import com.ak.guard.common.KeysHolder;
import com.ak.guard.confidentiality.AESConfidential;
import com.ak.guard.confidentiality.Confidential;
import com.ak.guard.confidentiality.ConfidentialReqRes;
import com.ak.guard.confidentiality.keys.ConfidentialKeys;
import com.ak.guard.confidentiality.keys.EC25519ConfidentialKeys;
import com.ak.guard.confidentiality.keys.ECDHKeyExchange;
import com.ak.guard.confidentiality.keys.KeyExchange;
import com.ak.guard.integrity.Ed25519Integrity;
import com.ak.guard.integrity.Integrity;
import com.ak.guard.integrity.keys.Ed25519IntegrityKeys;
import com.ak.guard.integrity.keys.IntegrityKeys;
import com.ak.guard.integrity.models.SignatureRequest;
import com.ak.guard.integrity.models.VerificationRequest;
import com.ak.guard.model.CipherRequest;
import com.ak.guard.model.CipherResponse;
import com.ak.guard.model.f_M;
import com.fasterxml.jackson.core.JsonProcessingException;

public class FIU {
	
	private static Logger log = Logger.getLogger("FIU");

	private Confidential confidential = new AESConfidential();
	private ConfidentialKeys confidentialKeys = new EC25519ConfidentialKeys();
	private KeyExchange keyExchange = new ECDHKeyExchange();
	private Integrity integrity = new Ed25519Integrity();
	private IntegrityKeys integrityKeys = new Ed25519IntegrityKeys();

	
	public void sendRequest() throws Exception {
		AA aa = new AA();
		AlgorithmParameterSpec f_ECAlgoParamSpec = confidentialKeys.DHParamasAlgo();
		KeyPair f_KeyPair = confidentialKeys.GenerateDHKeyPair(f_ECAlgoParamSpec);
		PrivateKey f_Privatekey = f_KeyPair.getPrivate();
		PublicKey f_PublicKey = f_KeyPair.getPublic();
		byte[] f_Encoded_Nonce =  CachableSingletons.randomPR256(); 
		String conset_artefact = "This is sent by FIU";
		f_M message = constructMessageForFIP(f_ECAlgoParamSpec, f_PublicKey, f_Encoded_Nonce, conset_artefact);
		
		KeyPair f_SignKP = integrityKeys.generateEdAsymmetricKey();
		PrivateKey f_SignPrivatekey = f_SignKP.getPrivate();
		PublicKey f_SignPublicKey = f_SignKP.getPublic();
		KeysHolder.setF_PrivateKey(f_Privatekey);
		KeysHolder.setF_PublicKey(f_PublicKey);
		KeysHolder.setF_SignPrivateKey(f_SignPrivatekey);
		KeysHolder.setF_SignPublicKey(f_SignPublicKey);
		KeysHolder.setF_ECAlgoParamSpec(f_ECAlgoParamSpec);
		KeysHolder.setEncodedOriginNonce(CommonUtil.bytesAsString(f_Encoded_Nonce));
		SignatureRequest signatureRequest = new SignatureRequest(message.toString(), f_SignPrivatekey);
		byte[] f_EncodedSignedMessage = integrity.SignatureGeneration(signatureRequest);
		System.out.println("signature encoded:" + CommonUtil.bytesAsString(f_EncodedSignedMessage));
		CipherRequest request = new CipherRequest(CommonUtil.bytesAsString(f_EncodedSignedMessage), message);
				aa.sendFIUtoAA(request);
	}

	public void sendAAtoFIU(CipherResponse responseP)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		VerificationRequest verificationRequest = new VerificationRequest(responseP.getP_M().toString(), KeysHolder.getA_SignPublicKey(), responseP.getSign().getBytes());
		
		boolean isverifiedAtFIU = integrity.SignatureVerification(verificationRequest);
		byte[] f_EncodedSecretKey = keyExchange.DHSharedKeyAlgo(KeysHolder.getP_PublicKey(), KeysHolder.getF_PrivateKey());
		System.out.println("secret key encoded:" + CommonUtil.bytesAsString(f_EncodedSecretKey));
		byte[] f_EncodedSessionKey = keyExchange.GenerateSessionKeyAlgo(f_EncodedSecretKey, KeysHolder.getEncodedOriginNonce().getBytes(),
				KeysHolder.getEncodedRemoteNonce().getBytes());
		System.out.println("session key :" + CommonUtil.bytesAsString(f_EncodedSessionKey));
		
		ConfidentialReqRes confidentialReqRes = new ConfidentialReqRes(null, responseP.getP_M().getCipherText(), f_EncodedSessionKey, KeysHolder.getEncodedRemoteNonce().getBytes(),
				KeysHolder.getEncodedOriginNonce().getBytes());
		
		confidentialReqRes = confidential.FIDataDecrypt(confidentialReqRes);
		System.out.println("plain text encoded:" + CommonUtil.bytesAsString(confidentialReqRes.getEncodedPlainText()));

	}
	
	public f_M constructMessageForFIP(AlgorithmParameterSpec ecAlgoParamsSpec, Key publicKey, byte[] encodedNonce,
			String data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException, JsonProcessingException {
		log.log(Level.INFO, "Constructing message");
		f_M m = new f_M();
		m.setDh_params(ecAlgoParamsSpec.toString());
		m.setDhpk(new String(publicKey.getEncoded()));
		m.setJsonRequest(data);
		m.setRand(encodedNonce);
		
		System.out.println("f_M : " + m.toString());
		log.log(Level.INFO, "Successfully constructed message");
		return m;
	}

	public void sendToAA(String message, String signMessage) {
		log.log(Level.INFO, "Dispatching message to AA");
		System.out.println("{ signMessage:" + signMessage + ", message:" + message);
		log.log(Level.INFO, "Successfully dispacted message to AA");
	}
}
