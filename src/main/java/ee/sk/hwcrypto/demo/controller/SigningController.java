/**
 * DSS Hwcrypto Demo
 *
 * Copyright (c) 2015 Estonian Information System Authority
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package ee.sk.hwcrypto.demo.controller;

import ee.sk.hwcrypto.demo.model.*;
import ee.sk.hwcrypto.demo.model.Result;
import ee.sk.hwcrypto.demo.signature.FileSigner;
import ee.sk.utils.ConfigManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.*;
import org.w3c.dom.Node;

import javax.xml.soap.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

@RestController
public class SigningController {

    private static final Logger log = LoggerFactory.getLogger(SigningController.class);
    @Autowired
    private SigningSessionData session;
    @Autowired
    private FileSigner signer;

    SignatureHandler signatureHandler;

    @RequestMapping(value="/upload", method= RequestMethod.POST)
    public Result handleUpload(@RequestParam MultipartFile file) {
        log.debug("Handling file upload for file " + file.getOriginalFilename());
        try {
            session.setUploadedFile(FileWrapper.create(file));
            return Result.resultOk();
        } catch (IOException e) {
            log.error("Error reading bytes from uploaded file " + file.getOriginalFilename(), e);
        }
        return Result.resultUploadingError();
    }

    @RequestMapping(value="/generateHash", method = RequestMethod.POST)
    public Digest generateHash(@RequestParam String cert) {
        log.debug("Generating hash from cert " + cert);
        configManagerInit();

        Digest digest = new Digest();
        try {
            signatureHandler = new SignatureHandler();
            String data = signatureHandler.prepareContract(cert);
            System.out.println("signature is ready ");
            //Data on hash allkirjastamiseks
            digest.setHex(data);
            digest.setResult(Result.OK);
        } catch (Exception e) {
            log.error("Error ", e);
            digest.setResult(Result.ERROR_GENERATING_HASH);
        }
        return digest;
    }

    @RequestMapping(value="/createContainer", method = RequestMethod.POST)
    public Result createContainer(@RequestParam String signatureInHex) {
        log.debug("Creating container for signature " + signatureInHex);
        //session.setSignatureInHex(signatureInHex);
        try {
            //session.setSignedFile(signer.signDocument(signatureInHex));
            signatureHandler.signDocument(signatureInHex);
            return Result.resultOk();
        } catch (Exception e) {
            log.error("Error Signing document", e);
        }
        return Result.resultSigningError();
    }

    @RequestMapping(value="/identify", method = RequestMethod.POST)
    public Result identifyUser(@RequestParam String certificate) {
        log.info("CERTIFICATE " + certificate.toString());
        try {
            /*the certification selection is bound the the lifecycle of the window object: re-loading the page invalidates the selection and calling sign() is not possible.*/
            CertificateFactory cf =  CertificateFactory.getInstance("X.509");
            byte[] bytes = Base64.getDecoder().decode(certificate);
            InputStream stream = new ByteArrayInputStream(bytes);
            X509Certificate cert = (X509Certificate)cf.generateCertificate(stream);
            cert.checkValidity();
            log.info("NAME " + cert.getSubjectDN().getName());
            session.setPersonalData(cert.getSubjectDN().getName());
            //TODO save user cert.getSubjectDN().getName()
            return Result.resultOk();
        } catch (Exception e) {
            log.error("Error Signing document", e);
        }
        return Result.resultOk();
    }

    /*
    MobileAuthenticate
    MobileSign
    MobileCreateSignature
    sisendiks telefoninumber ja isikukood.

    java InstallCert [host]:[port]

    keytool -exportcert -alias [host_from_installcert_output] -keystore jssecacerts -storepass ["changeit" is default] -file [host].cer

    keytool -importcert -alias [host] -keystore [path to system keystore] -storepass [your_keystore_password] -file [host].cer

    */
    @RequestMapping(value="/mobileauth", method = RequestMethod.POST)
    public void mobileAuth(@RequestParam String id,@RequestParam String phoneNumber){
        //TODO assign correct parameters
        MobileAuthenticate mobileAuthenticate = new MobileAuthenticate("14212128025", "EE", "+37200007", "EST", "Testimine", "Beer tastes good!", "", "asynchClientServer", "", "", "");
        String req = mobileAuthenticate.query();
        SOAPMessage result = SOAPQuery(req);
        printSOAPResponse(result);
        //TODO create session from SOAPMessage response
    }

    @RequestMapping(value="/mobilesign", method = RequestMethod.POST)
    public void startsession(){
        try{
            //Andmefailil 4 MB limiit, kui see ületatakse, siis tuleks saata ainult räsi
            System.out.println("mobilesign");
            //TODO seda siin enam vaja pole sest päris rakenduses tuleks kõige alguses ära confida ja see meelde jätta
            configManagerInit();

            //Alustame sessiooni (saadame andmefaili)
            //See peaks olema ilmselt eraldi üks blokk
            MobileSign mobileSign = new MobileSign();
            String startSessionQuery = mobileSign.startSession();
            SOAPMessage startSessionResponse = SOAPQuery(startSessionQuery);

            //Vaatame kas sessioon sai ilusti alustatud ja eraldame sessiooni koodi mis tarvis järgmisteks päringuteks
            String[] responseParameters = parseStartSessionResponse(startSessionResponse);
            String status = responseParameters[0];
            String sessCode = responseParameters[1];
            //Sessioon alustatud

            System.out.println("status " + status);
            System.out.println("sesscode " + sessCode);

            if(status.equalsIgnoreCase("OK")){
                //TODO get variables from sesion info
                //Make the query to sign
                //Saab lisa parameetreid panna kui tarvis nt. mida kuvatakse kliendi telefonis vt. mobileSignQuery parameetreid
                String mobileSignQuery = mobileSign.mobileSignQuery(sessCode, "14212128025", "+37200007", "", "Testimine", "", "EST", "", "", "", "", "", "", "asynchClientServer", "", "true", "true");
                SOAPMessage mobileSignSessionResponse = SOAPQuery(mobileSignQuery);
                //Allkirjastamise päring tehtud

                //For debug
                //printSOAPResponse(mobileSignSessionResponse);

                //1. status 2. statuscode 3.challengeid
                //TODO challenge id tuleks kuvada kasutajale, selle kaudu on võimalik kasutajal veenduda päringu autentsuses
                String[] mobileSignParameters = parseMobileSignResponse(mobileSignSessionResponse);
                String mobileStatus = mobileSignParameters[0];
                //Check if the user signed
                if(mobileStatus.equalsIgnoreCase("OK")){
                    String statusInfoQuery = mobileSign.getStatusInfo(sessCode,"true","true");
                    //This is filled when the signature is given
                    SOAPMessage statusResponse = SOAPQuery(statusInfoQuery);

                    //For debug
                    //printSOAPResponse(statusResponse);

                    //Vaatame kas allkiri sai antud
                    //Võimalikud koodid mis siit tulla saavad lk37 StatusCode all
                    //http://www.sk.ee/upload/files/DigiDocService_spec_est.pdf
                    String signatureStatus = parseGetStatusInfo(statusResponse);
                    if(signatureStatus.equalsIgnoreCase("SIGNATURE")){
                        //Allkiri on failil olemas küsime nüüd faili teenuselt
                        String getSignedDocumentQuery = mobileSign.getSignedDoc(sessCode);
                        SOAPMessage getSignedDocumentResponse = SOAPQuery(getSignedDocumentQuery);
                        printSOAPResponse(getSignedDocumentResponse);
                        String[] result = parseGetSignedDoc(getSignedDocumentResponse);
                        String docStatus = result[0];
                        String doc = result[1];
                        if(docStatus.equalsIgnoreCase("OK")){
                            //parse doc and save to disk
                            String escaped = escapeHtml(doc);
                            byte[] decodedBytes = org.apache.commons.codec.binary.Base64.decodeBase64(escaped);
                            try (OutputStream stream = new FileOutputStream("C:\\Users\\kalver\\IdeaProjects\\dss-hwcrypto-demo-master\\src\\main\\resources\\SOAP\\leping.bdoc")) {
                                stream.write(decodedBytes);
                            }
                        }
                    }
                }
            }

        }catch (Exception e){
            System.out.println("Startsession exp " + e);
        }

    }

    private SOAPMessage SOAPQuery(String req){
        try{
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();

            String url = "http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl";

            MessageFactory messageFactory = MessageFactory.newInstance();
            InputStream is = new ByteArrayInputStream(req.getBytes());
            SOAPMessage soapMessage = messageFactory.createMessage(null, is);
            SOAPPart soapPart = soapMessage.getSOAPPart();

            String serverURI = "https://www.openxades.org:8443/DigiDocService/";

            // SOAP Envelope
            SOAPEnvelope envelope = soapPart.getEnvelope();
            envelope.addNamespaceDeclaration("", url);
            MimeHeaders headers = soapMessage.getMimeHeaders();
            headers.addHeader("SOAPAction", "");
            soapMessage.saveChanges();

            SOAPMessage soapResponse = soapConnection.call(soapMessage, serverURI);

            return soapResponse;
        }catch (Exception e) {
            System.out.println("SOAP Exception " + e);
        }
        return null;
    }

    private String[] parseStartSessionResponse(SOAPMessage startSessionResponse) throws SOAPException{
        //TODO võibolla saab lihtsamalt ka kätte aga ei leidnud sellist viisi
        NodeList s2 = startSessionResponse.getSOAPBody().getChildNodes();
        String status = "";
        String sessCode = "";
        for(int i=0;i<s2.getLength();i++){
            Node n = s2.item(i);
            if(n.hasChildNodes()){
                NodeList children = n.getChildNodes();
                for(int j=0;j<children.getLength();j++){
                    Node child = children.item(j);
                    if(child.getNodeName().equalsIgnoreCase("Status")){
                        status=child.getTextContent();
                    }else if(child.getNodeName().equalsIgnoreCase("Sesscode")){
                        sessCode=child.getTextContent();
                    }
                }
            }
        }
        return new String[]{status,sessCode};
    }

    private String[] parseMobileSignResponse(SOAPMessage startSessionResponse) throws SOAPException{
        //TODO võibolla saab lihtsamalt ka kätte aga ei leidnud sellist viisi
        NodeList s2 = startSessionResponse.getSOAPBody().getChildNodes();
        String status = "";
        String statusCode = "";
        String challengeID = "";
        for(int i=0;i<s2.getLength();i++){
            Node n = s2.item(i);
            if(n.hasChildNodes()){
                NodeList children = n.getChildNodes();
                for(int j=0;j<children.getLength();j++){
                    Node child = children.item(j);
                    if(child.getNodeName().equalsIgnoreCase("Status")){
                        status=child.getTextContent();
                    }else if(child.getNodeName().equalsIgnoreCase("StatusCode")){
                        statusCode=child.getTextContent();
                    }else if(child.getNodeName().equalsIgnoreCase("ChallengeID")){
                        challengeID=child.getTextContent();
                    }
                }
            }
        }
        return new String[]{status,statusCode,challengeID};
    }

    private String parseGetStatusInfo(SOAPMessage startSessionResponse) throws SOAPException{
        //TODO võibolla saab lihtsamalt ka kätte aga ei leidnud sellist viisi
        NodeList s2 = startSessionResponse.getSOAPBody().getChildNodes();
        String status = "";
        for(int i=0;i<s2.getLength();i++){
            Node n = s2.item(i);
            if(n.hasChildNodes()){
                NodeList children = n.getChildNodes();
                for(int j=0;j<children.getLength();j++){
                    Node child = children.item(j);
                    if(child.getNodeName().equalsIgnoreCase("StatusCode")){
                        status=child.getTextContent();
                    }
                }
            }
        }
        return status;
    }

    private String[] parseGetSignedDoc(SOAPMessage startSessionResponse) throws SOAPException{
        //TODO võibolla saab lihtsamalt ka kätte aga ei leidnud sellist viisi
        NodeList s2 = startSessionResponse.getSOAPBody().getChildNodes();
        String status = "";
        String data = "";
        for(int i=0;i<s2.getLength();i++){
            Node n = s2.item(i);
            if(n.hasChildNodes()){
                NodeList children = n.getChildNodes();
                for(int j=0;j<children.getLength();j++){
                    Node child = children.item(j);
                    if(child.getNodeName().equalsIgnoreCase("Status")){
                        status=child.getTextContent();
                    }else if(child.getNodeName().equalsIgnoreCase("SignedDocData")){
                        data=child.getTextContent();
                    }
                }
            }
        }
        return new String[]{status,data};
    }



    private void printSOAPResponse(SOAPMessage soapResponse) {
        try{
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            Source sourceContent = soapResponse.getSOAPPart().getContent();
            System.out.print("\nResponse SOAP Message = ");
            StreamResult result = new StreamResult(System.out);
            transformer.transform(sourceContent, result);
        }catch (Exception e){
            System.out.print("\nPrinting exception " + e);
        }
    }

    private void configManagerInit(){
        ConfigManager.init("C:\\Users\\kalver\\IdeaProjects\\dss-hwcrypto-demo-master\\jdigidoc.cfg");
    }




}
