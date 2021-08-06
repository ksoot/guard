package com.ak.guard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import com.ak.guard.common.CommonUtil;

public class X509V3CreateExample {

	

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair pairCACert = CommonUtil.generateRSAKeyPair();
		KeyPair pairIntCert = CommonUtil.generateRSAKeyPair();
		KeyPair pairEndCert = CommonUtil.generateRSAKeyPair();
		PKCS10CertificationRequest certReq = generateRequest(pairEndCert);

		X509Certificate caCert  = X509V3CA.generateCACert(pairEndCert);
		X509Certificate intCert = X509V3CA.generateIntermediateCert(pairIntCert.getPublic(), pairCACert.getPrivate(), caCert);
		X509Certificate endCert = X509V3CA.generateEndEntityCert(pairEndCert.getPublic(), pairIntCert.getPrivate(), caCert, certReq);
		// create cert requsest for CA
	
		
	
		X509Certificate[] chain = {endCert, intCert, caCert};
		chain[0].verify(chain[1].getPublicKey());
		System.out.println("verified");
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		CertPath certPath = fact.generateCertPath(Arrays.asList(chain));
		byte[] encoded = certPath.getEncoded("PEM");
		// System.out.println(CommonUtil.bytesAsString(encoded));
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(Arrays.asList(chain));
		CertStore store = CertStore.getInstance("Collection", params, "BC");
		X509CertSelector selector = new X509CertSelector();
		selector.setSubject(new X500Principal("CN=Requested Test Certificate").getEncoded());
		Iterator certsIt = store.getCertificates(selector).iterator();
		while (certsIt.hasNext()) {
			X509Certificate cert = (X509Certificate) certsIt.next();
			System.out.println(cert.getSubjectX500Principal());
		}
		/*
		 * PemWriter pem = new PemWriter(new OutputStreamWriter(System.out)); PemObject
		 * obj = new PemObject("CERTIFICATE REQUEST", certReq.getEncoded());
		 * pem.writeObject(obj.generate()); pem.close();
		 */

		/*
		 * PemWriter pemWrt = new PemWriter( new OutputStreamWriter(System.out));
		 * pemWrt.writeObject(new PemObject("X.509", certs[0].getEncoded()).generate());
		 * pemWrt.writeObject(new PemObject("X.509", certs[1].getEncoded()).generate());
		 * pemWrt.close();
		 */

		System.out.println("valid certificate generated");
	}

	private static ByteArrayOutputStream storeDERInMemory(X509Certificate cert)
			throws CertificateEncodingException, IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		bOut.write(cert.getEncoded());
		bOut.close();
		return bOut;
	}

	private static List<X509Certificate> loadDERFromMemory(ByteArrayOutputStream bOut)
			throws IOException, CertificateException, NoSuchProviderException {
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		// read certificate from memory
		InputStream in = new ByteArrayInputStream(bOut.toByteArray());
		// create the certificate factory
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate x509Cert;
		while ((x509Cert = (X509Certificate) fact.generateCertificate(in)) != null) {
			certList.add(x509Cert);
		}
		// the above part can also be written like below.
		// certList = (List<X509Certificate>) fact.generateCertificates(in);

		return certList;
	}

	private static ByteArrayOutputStream storePEMInMemory(X509Certificate cert)
			throws CertificateEncodingException, IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PemWriter pemWrt = new PemWriter(new OutputStreamWriter(bOut));
		PemObject obj = new PemObject("X.509", cert.getEncoded());
		pemWrt.writeObject(obj.generate());
		pemWrt.close();
		bOut.close();
		return bOut;
	}

	private static X509Certificate loadPEMFromMemory(ByteArrayOutputStream bOut)
			throws IOException, CertificateException, NoSuchProviderException {
		// read certificate from memory
		InputStream in = new ByteArrayInputStream(bOut.toByteArray());
		PemReader reader = new PemReader(new InputStreamReader(in));
		PemObject obj = reader.readPemObject();
		// create the certificate factory
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		// read the certificate by passing input stream to factory
		X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(null);
		return x509Cert;
	}

	private static File storeDEROnDisK(X509Certificate cert) throws IOException, CertificateEncodingException {
		File file = new File("cert.der");
		FileOutputStream fOut = new FileOutputStream(file);
		fOut.write(cert.getEncoded());
		fOut.flush();
		fOut.close();
		return file;
	}

	private static X509Certificate loadDERFromDisk(File file)
			throws IOException, CertificateException, NoSuchProviderException {
		// read certificate from disk
		FileInputStream fIn = new FileInputStream(file);
		// create the certificate factory
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		// read the certificate by passing input stream to factory
		X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(fIn);
		return x509Cert;
	}

	private static File storePEMOnDisK(X509Certificate cert)
			throws PemGenerationException, IOException, CertificateEncodingException {
		File file = new File("cert.der");
		FileOutputStream fOut = new FileOutputStream(file);
		PemWriter pemWrt = new PemWriter(new OutputStreamWriter(fOut));
		PemObject obj = new PemObject("X.509", cert.getEncoded());
		pemWrt.writeObject(obj.generate());
		pemWrt.close();
		fOut.flush();
		return file;

	}

	private static X509Certificate loadPEMFromDisK(File file)
			throws PemGenerationException, IOException, CertificateException, NoSuchProviderException {
		// read certificate from disk
		FileInputStream fIn = new FileInputStream(file);
		// create the certificate factory
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		// read the certificate by passing input stream to factory
		X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(fIn);
		return x509Cert;
	}

	public static PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception {
		// create a SubjectAlternativeName extension value
		GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test"));
		// create the extensions object and add it as an attribute
		Vector oids = new Vector();
		Vector values = new Vector();
		oids.add(X509Extensions.SubjectAlternativeName);
		values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
		X509Extensions extensions = new X509Extensions(oids, values);
		Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
		return new PKCS10CertificationRequest("SHA256withRSA", new X500Principal("CN=Requested Test Certificate"),
				pair.getPublic(), new DERSet(attribute), pair.getPrivate());
	}

}
