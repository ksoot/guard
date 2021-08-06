package com.ak.guard;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ak.guard.common.CommonUtil;
import com.ak.guard.common.KeysHolder;
import com.ak.guard.integrity.Ed25519Integrity;
import com.ak.guard.integrity.Integrity;
import com.ak.guard.integrity.keys.Ed25519IntegrityKeys;
import com.ak.guard.integrity.keys.IntegrityKeys;
import com.ak.guard.integrity.models.SignatureRequest;
import com.ak.guard.integrity.models.VerificationRequest;
import com.ak.guard.model.CipherRequest;
import com.ak.guard.model.CipherResponse;

public class AA {

	private static Logger log = Logger.getLogger("AA");
	private Integrity integrity = new Ed25519Integrity();
	private IntegrityKeys integrityKeys = new Ed25519IntegrityKeys();

	public void sendFIUtoAA(CipherRequest request) throws Exception {
		FIP fip = new FIP();
		VerificationRequest verificationRequest = new VerificationRequest(request.getf_M().toString(), KeysHolder.getF_SignPublicKey(), request.getSign().getBytes());
		boolean isverifiedAtAA = integrity.SignatureVerification(verificationRequest);
		System.out.println("sign verified At AA :" + isverifiedAtAA);
		if (isverifiedAtAA != true) {
			System.out.println("signature not verified hence not forwarding to FIP");
			throw new Exception();
		}
		System.out.println("signature verified successfully forwarding to FIP");
		KeyPair a_SignKP = integrityKeys.generateEdAsymmetricKey();
		PrivateKey a_SignPrivatekey = a_SignKP.getPrivate();
		PublicKey a_SignPublicKey = a_SignKP.getPublic();
		KeysHolder.setA_SignPrivateKey(a_SignPrivatekey);
		KeysHolder.setA_SignPublicKey(a_SignPublicKey);
		SignatureRequest signatureRequest = new SignatureRequest(request.getf_M().toString(), a_SignPrivatekey);
		byte[] a_EncodedSignedMessage = integrity.SignatureGeneration(signatureRequest);
		System.out.println("signature encoded:" + CommonUtil.bytesAsString(a_EncodedSignedMessage));
		CipherRequest newRequest = new CipherRequest(CommonUtil.bytesAsString(a_EncodedSignedMessage), request.getf_M());
		System.out.println("a_EncodedSignedMessage :" + a_EncodedSignedMessage);
		fip.sendAAtoFIP(newRequest);

	}

	public void sendFIPtoAA(CipherResponse response) throws Exception {
		FIU fiu = new FIU();
		VerificationRequest verificationRequest = new VerificationRequest(response.getP_M().toString(), KeysHolder.getP_SignPublicKey(),
				response.getSign().getBytes());
		
		boolean isverifiedAtFIPtoAA = integrity.SignatureVerification(verificationRequest);
		System.out.println("sign verified At AA :" + isverifiedAtFIPtoAA);
		if (isverifiedAtFIPtoAA != true) {
			System.out.println("signature not verified hence not forwarding to FIU");
			throw new Exception();
		}
		System.out.println("signature verified successfully forwarding to FIU");
		/*
		 * KeyPair a_SignKP = util.generateEdAsymmetricKey(); PrivateKey
		 * a_SignPrivatekey = a_SignKP.getPrivate(); PublicKey a_SignPublicKey =
		 * a_SignKP.getPublic(); KeysHolder.setA_SignPrivateKey(a_SignPrivatekey);
		 * KeysHolder.setA_SignPublicKey(a_SignPublicKey);
		 */
		SignatureRequest signatureRequest = new SignatureRequest(response.getP_M().toString(), KeysHolder.getA_SignPrivateKey());
		
		byte[] a_EncodedSignedMessage = integrity.SignatureGeneration(signatureRequest);
		System.out.println("signature encoded:" + CommonUtil.bytesAsString(a_EncodedSignedMessage));
		System.out.println("a_EncodedSignedMessage :" + a_EncodedSignedMessage);
		CipherResponse responseP = new CipherResponse(response.getP_M(), CommonUtil.bytesAsString(a_EncodedSignedMessage), null);
		fiu.sendAAtoFIU(responseP);

	}
	
	public void sendToFIP(String message, String signMessage) {
		log.log(Level.INFO, "Dispatching message to FIP");
		System.out.println("{ signMessage:" + signMessage + ", message:" + message);
		log.log(Level.INFO, "Successfully dispatched message to FIP");
	}
}
