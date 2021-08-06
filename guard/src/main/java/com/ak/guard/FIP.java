package com.ak.guard;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;

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
import com.ak.guard.model.p_M;

public class FIP {
	private static Logger log = Logger.getLogger("FIP");
	private CommonUtil util = new CommonUtil();
	private Confidential confidential = new AESConfidential();
	private ConfidentialKeys confidentialKeys = new EC25519ConfidentialKeys();
	private KeyExchange keyExchange = new ECDHKeyExchange();
	private Integrity integrity = new Ed25519Integrity();
	private IntegrityKeys integrityKeys = new Ed25519IntegrityKeys();
	

	public void sendAAtoFIP(CipherRequest request) throws Exception {
		AA aa = new AA();
		VerificationRequest verificationRequest = new VerificationRequest(request.getf_M().toString(), KeysHolder.getA_SignPublicKey(), request.getSign().getBytes());
		
		boolean isverifiedAtFIP = integrity.SignatureVerification(verificationRequest);
		System.out.println("sign verified At FIP :" + isverifiedAtFIP);
		if (isverifiedAtFIP != true) {
			System.out.println("signature not verified At FIP hence aborting");
			throw new Exception();
		}
		System.out.println("signature verified successfully at FIP end");
		boolean isAgreeableParams = util.checkIfDHParamsAgreeable(KeysHolder.getF_ECAlgoParamSpec());
		AlgorithmParameterSpec p_ECAlgoParamSpec = null;
		KeyPair p_KeyPair = null;
		PrivateKey p_Privatekey = null;
		PublicKey p_PublicKey = null;
		if (isAgreeableParams) {
			p_ECAlgoParamSpec = KeysHolder.getF_ECAlgoParamSpec();
		} else {
			p_ECAlgoParamSpec = confidentialKeys.DHParamasAlgo();
		}
		p_KeyPair = confidentialKeys.GenerateDHKeyPair(p_ECAlgoParamSpec);
		p_Privatekey = p_KeyPair.getPrivate();
		p_PublicKey = p_KeyPair.getPublic();
		byte[] p_Encoded_Nonce = CachableSingletons.randomNo256();
		KeysHolder.setEncodedRemoteNonce(CommonUtil.bytesAsString(p_Encoded_Nonce));
		KeysHolder.setP_PrivateKey(p_Privatekey);
		KeysHolder.setP_PublicKey(p_PublicKey);

		byte[] p_EncodedSecretKey = keyExchange.DHSharedKeyAlgo(KeysHolder.getF_PublicKey(), p_Privatekey);
		System.out.println("secret key encoded:" + CommonUtil.bytesAsString(p_EncodedSecretKey));
		byte[] p_EncodedSessionKey = keyExchange.GenerateSessionKeyAlgo(p_EncodedSecretKey, KeysHolder.getEncodedOriginNonce().getBytes(),
				KeysHolder.getEncodedRemoteNonce().getBytes());
		System.out.println("session key encoded:" + CommonUtil.bytesAsString(p_EncodedSessionKey));
		ConfidentialReqRes confidentialReqRes = new ConfidentialReqRes(CommonUtil.encodedBytes("This is sent by FIP".getBytes()), null, p_EncodedSessionKey, KeysHolder.getEncodedRemoteNonce().getBytes(),
				KeysHolder.getEncodedOriginNonce().getBytes());
		
		confidentialReqRes = confidential.FIDataEncrypt(confidentialReqRes);
		System.out.println("cipher text encoded :" + CommonUtil.bytesAsString(confidentialReqRes.getEncodedCipherText()));
		p_M p_Message = constructMessageForFIU(p_ECAlgoParamSpec, p_PublicKey, KeysHolder.getEncodedRemoteNonce(),
				confidentialReqRes.getEncodedCipherText());
		KeyPair p_SignKP = integrityKeys.generateEdAsymmetricKey();
		PrivateKey p_SignPrivatekey = p_SignKP.getPrivate();
		PublicKey p_SignPublicKey = p_SignKP.getPublic();

		KeysHolder.setP_SignPrivateKey(p_SignPrivatekey);
		KeysHolder.setP_SignPublicKey(p_SignPublicKey);
		SignatureRequest signatureRequest = new SignatureRequest(p_Message.toString(), p_SignPrivatekey);
		byte[] p_EncodedSignedMessage = integrity.SignatureGeneration(signatureRequest);
		System.out.println("signature encoded:" + CommonUtil.bytesAsString(p_EncodedSignedMessage));
		CipherResponse response = new CipherResponse(p_Message,CommonUtil.bytesAsString(p_EncodedSignedMessage), null);
		aa.sendFIPtoAA(response);

	}

	public p_M constructMessageForFIU(AlgorithmParameterSpec ecAlgoParamsSpec, Key publicKey, String encodedNonce,
			byte[] cipherText) {
		log.log(Level.INFO, "Constructing message");
		p_M m = new p_M();
		m.setDh_params(ecAlgoParamsSpec.toString());
		m.setDhpk(new String(publicKey.getEncoded()));
		m.setCipherText(cipherText);
		m.setStatus("OK");
		m.setRand(encodedNonce);
		
		System.out.println("f_M : " + m.toString());
		log.log(Level.INFO, "Successfully constructed message");
		return m;
	}

	public void sendToFIU(String message, String signMessage) {
		log.log(Level.INFO, "Dispatching message to AA");
		System.out.println("{ signMessage:" + signMessage + ", message:" + message);
		log.log(Level.INFO, "Successfully dispacted message to AA");
	}
}
