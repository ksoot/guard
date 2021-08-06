package com.ak.guard;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import com.ak.guard.common.CommonUtil;

public class X509V3CA {

	private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week

	public static X509Certificate generateCACert(KeyPair pair)
			throws InvalidKeyException, NoSuchProviderException, SignatureException {
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(1));
		certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
		certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
		return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}

	public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
			throws Exception {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(1));
		certGen.setIssuerDN(caCert.getSubjectX500Principal());
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
		certGen.setSubjectDN(new X500Principal("CN=Test Intermediate Certificate"));
		certGen.setPublicKey(intKey);
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		// certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new
		// SubjectKeyIdentifierStructure(intKey));
		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
		certGen.addExtension(X509Extensions.KeyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
		return certGen.generateX509Certificate(caKey, "BC");
	}

	public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert,
			PKCS10CertificationRequest request) throws Exception {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(caCert.getSubjectX500Principal());
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		certGen.setSubjectDN(new X500Principal("CN=Requested Test Certificate"));
		certGen.setPublicKey(request.getPublicKey("BC"));
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		// certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new
		// SubjectKeyIdentifierStructure(entityKey));
		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		ASN1Set attributes = request.getCertificationRequestInfo().getAttributes();
		for (int i = 0; i != attributes.size(); i++) {
			Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));
			// process extension request
			if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
				Enumeration e = extensions.oids();
				while (e.hasMoreElements()) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
					X509Extension ext = extensions.getExtension(oid);
					certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
				}
			}
		}
		return certGen.generateX509Certificate(caKey, "BC");
	}

	public static X509Certificate[] generateCertificate(PKCS10CertificationRequest request) throws Exception {
		return null;
	}
}
