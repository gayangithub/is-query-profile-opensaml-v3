package org.wso2.carbon.identity.saml.profile.query.test;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeQueryBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.wso2.carbon.identity.saml.profile.query.util.SAMLQueryRequestUtil;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.UUID;


public class SAMLQueryRequestClient {

    public static void main(String[] ags) throws Exception {
        String REQUEST_ID = "_" + UUID.randomUUID().toString();
        final String ISSUER_ID = "travelocity.com";
        final String NAME_ID = "admin";
        String body = "";
        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter =
                new DateTime(issueInstant.getMillis() +
                        (long) SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 *
                                1000);

        AttributeQuery attributeQuery = new AttributeQueryBuilder().buildObject();
        Issuer issuer = new IssuerBuilder().buildObject();
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameID = new NameIDBuilder().buildObject();
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        SubjectConfirmationData subjectConfirmationData =
                new SubjectConfirmationDataBuilder().buildObject();
        /*
        SignatureBuilder builder = new SignatureBuilder();
        Signature signature = builder.buildObject();
        Credential credential =new BasicX509Credential();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        */
        issuer.setValue(ISSUER_ID);
        nameID.setValue(NAME_ID);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        subject.setNameID(nameID);

        attributeQuery.setVersion(SAMLVersion.VERSION_20);
        attributeQuery.setID(REQUEST_ID);
        attributeQuery.setIssueInstant(issueInstant);
        attributeQuery.setIssuer(issuer);
        attributeQuery.setSubject(subject);
        //attributeQuery.setSignature(signature);

        try {
            String requestMessage = SAMLQueryRequestUtil.marshall(attributeQuery);
            body = requestMessage;
            System.out.println(body);
        } catch (Exception e) {

        }


        String trustStore = "C:\\Downloads\\wso2\\wso2is-5.1.0\\repository\\resources\\security\\client-truststore.jks";
        String trustStorePass = "wso2carbon";
        String endpoint = "https://localhost:9443/services/SAMLQueryService";
        String soapAction = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Test";

        // Setting trust store.  This is required if you are using SSL (HTTPS) transport
        // WSO2 Carbon server's certificate must be in the trust store file that is defined below
        // You need to set this for security scenario 01

        System.setProperty("javax.net.ssl.trustStore", trustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);


        // creating axis2 configuration using repo that we defined and using default axis2.xml.
        // if you want to use a your own axis2.xml, please configure the location for it with out
        // passing null

        ConfigurationContext configurationContext = null;
        ServiceClient serviceClient = null;

        try {
            configurationContext = ConfigurationContextFactory.
                    createConfigurationContextFromFileSystem(null, null);
            serviceClient = new ServiceClient(configurationContext, null);
//            serviceClient.engageModule("rampart");
//            serviceClient.engageModule("addressing");
        } catch (AxisFault axisFault) {
            System.err.println("Error creating axis2 service client !!!");
            axisFault.printStackTrace();
            System.exit(0);
        }

        Options options = new Options();

        // security scenario 01 must use the SSL.  So we need to call HTTPS endpoint of the service


        options.setTo(new EndpointReference(endpoint));


        // set the operation that you are calling in the service.

        options.setAction(soapAction);

        // set above options to service client
        serviceClient.setOptions(options);

        // set message to service
        OMElement result = null;
        try {
            result = serviceClient.sendReceive(AXIOMUtil.stringToOM(body));
            System.out.println("Message is sent");
        } catch (AxisFault axisFault) {
            System.err.println("Error invoking service !!!");
            axisFault.printStackTrace();
            System.exit(0);
        } catch (javax.xml.stream.XMLStreamException e) {
            e.printStackTrace();
        }

        // printing return message.
        if (result != null) {
            System.out.println(result.toString());
        } else {

            System.out.println("ERROR ERROR");
        }
        System.exit(0);

    }

}
