package com.ds.pdfbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SigningTest implements SignatureInterface {

	private static BouncyCastleProvider provider = new BouncyCastleProvider();

	private PrivateKey privKey;

	private Certificate[] cert;

	public SigningTest(KeyStore keystore, char[] pin) {
		try {
			Enumeration<String> aliases = keystore.aliases();
			String alias = null;
			if (aliases.hasMoreElements())
				alias = aliases.nextElement();
			else
				throw new RuntimeException("Could not find Key");
			privKey = (PrivateKey) keystore.getKey(alias, pin);
			cert = keystore.getCertificateChain(alias);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@SuppressWarnings("deprecation")
	public byte[] sign(InputStream content) throws SignatureException, IOException {
		CMSProcessableInputStream input = new CMSProcessableInputStream(content);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		// CertificateChain
		List<Certificate> certList = Arrays.asList(cert);

		CertStore certStore = null;
		try {
			certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), provider);
			gen.addSigner(privKey, (X509Certificate) certList.get(0), CMSSignedGenerator.DIGEST_SHA256);
			gen.addCertificatesAndCRLs(certStore);
			CMSSignedData signedData = gen.generate(input, false, provider);
			return signedData.getEncoded();
		} catch (Exception e) {
			// should be handled
			e.printStackTrace();
		}
		throw new RuntimeException("Problem while preparing signature");
	}

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
		FileNotFoundException, IOException, COSVisitorException, SignatureException, Exception {
		File document = new File("D:\\****-Docs\\certTechnician.pdf");
		PDDocument pdDocument = PDDocument.load(document);
		addSignature(pdDocument, "D:\\****-Docs\\sample02.pfx", "apples");

		File outputDocument = new File("D:\\****-Docs\\DigitallySignedcertTechnician.pdf");
		FileInputStream fis = new FileInputStream(document);
		FileOutputStream fos = new FileOutputStream(outputDocument);
		byte[] buffer = new byte[8 * 1024];
		int c;
		while ((c = fis.read(buffer)) != -1) {
			fos.write(buffer, 0, c);
		}
		fis.close();
		fis = new FileInputStream(outputDocument);

		pdDocument.saveIncremental(fis, fos);
		pdDocument.close();

		document = new File("D:\\****-Docs\\DigitallySignedcertTechnician.pdf");
		pdDocument = PDDocument.load(document);
		addSignature(pdDocument, "D:\\****-Docs\\sample01.pfx", "battery");

		outputDocument = new File("D:\\****-Docs\\DigitallySignedcertTechnicianAgain.pdf");
		fis = new FileInputStream(document);
		fos = new FileOutputStream(outputDocument);
		buffer = new byte[8 * 1024];

		while ((c = fis.read(buffer)) != -1) {
			fos.write(buffer, 0, c);
		}
		fis.close();
		fis = new FileInputStream(outputDocument);

		pdDocument.saveIncremental(fis, fos);
		pdDocument.close();

		System.out.println("File created.");

	}

	static void addSignature(PDDocument pdDocument, String filePath, String pwd) throws Exception {
		File ksFile = new File(filePath);
		KeyStore keystore = KeyStore.getInstance("PKCS12", provider);
		char[] pin = pwd.toCharArray();
		keystore.load(new FileInputStream(ksFile), pin);
		SigningTest signing = new SigningTest(keystore, pin.clone());
		// signing.signPDF(document);

		// create signature dictionary
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// subfilter for basic and PAdES Part 2 signatures
		signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		signature.setName("signer name");
		signature.setLocation("signer location");
		signature.setReason("reason for signature");

		// the signing date, needed for valid signature
		signature.setSignDate(Calendar.getInstance());
//      SignatureOptions signatureOptions= new SignatureOptions();
//      signatureOptions.setVisualSignature();
		// register signature dictionary and sign interface
		pdDocument.addSignature(signature, signing);

	}
}

class CMSProcessableInputStream implements CMSProcessable {

	InputStream in;

	public CMSProcessableInputStream(InputStream is) {
		in = is;
	}

	public Object getContent() {
		return null;
	}

	public void write(OutputStream out) throws IOException, CMSException {
		// read the content only one time
		byte[] buffer = new byte[8 * 1024];
		int read;
		while ((read = in.read(buffer)) != -1) {
			out.write(buffer, 0, read);
		}
		in.close();
	}
}
