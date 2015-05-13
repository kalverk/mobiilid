package ee.sk.hwcrypto.demo.model;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.SignatureFactory;
import ee.sk.utils.ConfigManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Created by kalver on 8.05.2015.
 */
public class SignatureHandler {

    private Signature sig;

    public String prepareContract(String den) throws DigiDocException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());
        X509Certificate cert = parseCertificate(den);
        System.out.println("got cert " + cert.getSubjectDN().getName());
        SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_BDOC, SignedDoc.BDOC_VERSION_2_1);
        //SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        sdoc.setProfile(SignedDoc.BDOC_PROFILE_TM);
        System.out.println("creating sdoc " + sdoc.getMimeType());
        sdoc.addDataFile(new File("C:\\Users\\kalver\\IdeaProjects\\dss-hwcrypto-demo-master\\src\\main\\leping.txt"),
                "text/plain", DataFile.CONTENT_BINARY);
        System.out.println("DATAFILE ADDED " + BouncyCastleProvider.PROVIDER_NAME);
        sig = sdoc.prepareSignature(cert, null, null);
        sig.setProfile(SignedDoc.BDOC_PROFILE_TM);
        byte[] sidigest = sig.calculateSignedInfoDigest();
        System.out.println("PREPARED");
        //System.out.println("signature is prepared " + res.getSubject());
        return SignedDoc.bin2hex(sidigest);
    }

    public X509Certificate parseCertificate(String den) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] bytes = Base64.getDecoder().decode(den);
        return (X509Certificate)cf.generateCertificate(
                new ByteArrayInputStream(bytes));
    }

    public void signDocument(String signatureInHex) throws DigiDocException {
        sig.setSignatureValue(SignedDoc.hex2bin(signatureInHex));
        SignedDoc signedDoc = sig.getSignedDoc();
        signedDoc.writeToFile(new File("C:\\Users\\kalver\\IdeaProjects\\dss-hwcrypto-demo-master\\docs\\test.bdoc"));
    }

}
