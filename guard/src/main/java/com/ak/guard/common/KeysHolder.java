package com.ak.guard.common;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class KeysHolder {

	public static PrivateKey f_PrivateKey;
	public static PublicKey f_PublicKey;
	public static PrivateKey f_SignPrivateKey;
	public static PublicKey f_SignPublicKey;
	public static PrivateKey a_SignPrivateKey;
	public static PublicKey a_SignPublicKey;
	public static PrivateKey p_PrivateKey;
	public static PublicKey p_PublicKey;
	public static PrivateKey p_SignPrivateKey;
	public static PublicKey p_SignPublicKey;
	public static AlgorithmParameterSpec f_ECAlgoParamSpec;
	public static String encodedOriginNonce;
	public static String encodedRemoteNonce;
	
	public static PrivateKey getF_PrivateKey() {
		return f_PrivateKey;
	}
	public static void setF_PrivateKey(PrivateKey f_PrivateKey) {
		KeysHolder.f_PrivateKey = f_PrivateKey;
	}
	public static PublicKey getF_PublicKey() {
		return f_PublicKey;
	}
	public static void setF_PublicKey(PublicKey f_PublicKey) {
		KeysHolder.f_PublicKey = f_PublicKey;
	}
	public static PrivateKey getF_SignPrivateKey() {
		return f_SignPrivateKey;
	}
	public static void setF_SignPrivateKey(PrivateKey f_SignPrivateKey) {
		KeysHolder.f_SignPrivateKey = f_SignPrivateKey;
	}
	public static PublicKey getF_SignPublicKey() {
		return f_SignPublicKey;
	}
	public static void setF_SignPublicKey(PublicKey f_SignPublicKey) {
		KeysHolder.f_SignPublicKey = f_SignPublicKey;
	}
	public static PrivateKey getA_SignPrivateKey() {
		return a_SignPrivateKey;
	}
	public static void setA_SignPrivateKey(PrivateKey a_SignPrivateKey) {
		KeysHolder.a_SignPrivateKey = a_SignPrivateKey;
	}
	public static PublicKey getA_SignPublicKey() {
		return a_SignPublicKey;
	}
	public static void setA_SignPublicKey(PublicKey a_SignPublicKey) {
		KeysHolder.a_SignPublicKey = a_SignPublicKey;
	}
	public static PrivateKey getP_PrivateKey() {
		return p_PrivateKey;
	}
	public static void setP_PrivateKey(PrivateKey p_PrivateKey) {
		KeysHolder.p_PrivateKey = p_PrivateKey;
	}
	public static PublicKey getP_PublicKey() {
		return p_PublicKey;
	}
	public static void setP_PublicKey(PublicKey p_PublicKey) {
		KeysHolder.p_PublicKey = p_PublicKey;
	}
	public static PrivateKey getP_SignPrivateKey() {
		return p_SignPrivateKey;
	}
	public static void setP_SignPrivateKey(PrivateKey p_SignPrivateKey) {
		KeysHolder.p_SignPrivateKey = p_SignPrivateKey;
	}
	public static PublicKey getP_SignPublicKey() {
		return p_SignPublicKey;
	}
	public static void setP_SignPublicKey(PublicKey p_SignPublicKey) {
		KeysHolder.p_SignPublicKey = p_SignPublicKey;
	}

	public static AlgorithmParameterSpec getF_ECAlgoParamSpec() {
		return f_ECAlgoParamSpec;
	}
	
	public static void setF_ECAlgoParamSpec(AlgorithmParameterSpec f_ECAlgoParamSpec) {
		KeysHolder.f_ECAlgoParamSpec = f_ECAlgoParamSpec;
	}
	public static String getEncodedOriginNonce() {
		return encodedOriginNonce;
	}
	public static void setEncodedOriginNonce(String encodedOriginNonce) {
		KeysHolder.encodedOriginNonce = encodedOriginNonce;
	}
	public static String getEncodedRemoteNonce() {
		return encodedRemoteNonce;
	}
	public static void setEncodedRemoteNonce(String encodedRemoteNonce) {
		KeysHolder.encodedRemoteNonce = encodedRemoteNonce;
	}
	
	
}
