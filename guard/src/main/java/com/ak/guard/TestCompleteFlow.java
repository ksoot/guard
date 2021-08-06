package com.ak.guard;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestCompleteFlow {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FIU fiu = new FIU();
		fiu.sendRequest();
	}
}
