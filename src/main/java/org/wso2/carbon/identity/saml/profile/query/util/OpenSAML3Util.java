package org.wso2.carbon.identity.saml.profile.query.util;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidationProvider;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.provider.ApacheSantuarioSignatureValidationProviderImpl;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.SAML2SSOFederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.profile.query.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.builders.signature.SSOSigner;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import static org.opensaml.core.xml.util.XMLObjectSupport.buildXMLObject;
import static org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil.generateKSNameFromDomainName;

public class OpenSAML3Util {

    private static SSOSigner ssoSigner = null;
    private static RealmService realmService;
    private static Log log = LogFactory.getLog(OpenSAML3Util.class);


    public static Issuer getIssuer(String tenantDomain) throws IdentityException {

        Issuer issuer = new IssuerBuilder().buildObject();
        String idPEntityId = null;
        IdentityProvider identityProvider;
        int tenantId;

        if (StringUtils.isEmpty(tenantDomain) || "null".equals(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            try {
                tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw IdentityException.error("Error occurred while retrieving tenant id from tenant domain", e);
            }

            if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
                throw IdentityException.error("Invalid tenant domain - '" + tenantDomain + "'");
            }
        }

        IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);

        try {
            identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw IdentityException.error(
                    "Error occurred while retrieving Resident Identity Provider information for tenant " +
                            tenantDomain, e);
        }
        FederatedAuthenticatorConfig[] authnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        for (FederatedAuthenticatorConfig config : authnConfigs) {
            if (IdentityApplicationConstants.Authenticator.SAML2SSO.NAME.equals(config.getName())) {
                SAML2SSOFederatedAuthenticatorConfig samlFedAuthnConfig = new SAML2SSOFederatedAuthenticatorConfig(config);
                idPEntityId = samlFedAuthnConfig.getIdpEntityId();
            }
        }
        if (idPEntityId == null) {
            idPEntityId = IdentityUtil.getProperty(IdentityConstants.ServerConfig.ENTITY_ID);
        }
        issuer.setValue(idPEntityId);
        issuer.setFormat(SAMLSSOConstants.NAME_ID_POLICY_ENTITY);
        return issuer;
    }

    public static Assertion setSignature(Assertion response, String signatureAlgorithm, String digestAlgorithm,
                                         X509Credential cred) throws IdentityException {

        return (Assertion) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
    }

    public static Response setSignature(Response response, String signatureAlgorithm, String digestAlgorithm,
                                        X509Credential cred) throws IdentityException {

        return (Response) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     * Generic method to sign SAML Logout Request
     *
     * @param request
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param cred
     * @return
     * @throws IdentityException
     */
    private static SignableXMLObject doSetSignature(SignableXMLObject request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {
        SAMLQueryRequestUtil.doBootstrap();
        try {

            return setSSOSignature(request, signatureAlgorithm, digestAlgorithm, cred);


        } catch (Exception e) {
            throw IdentityException.error("Error while signing the XML object.", e);
        }
    }

    public static SignableXMLObject setSSOSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
        X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
        X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);

        String value;
        try {
            value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            throw IdentityException.error("Error occurred while retrieving encoded cert", e);
        }

        cert.setValue(value);
        data.getX509Certificates().add(cert);
        keyInfo.getX509Datas().add(data);
        signature.setKeyInfo(keyInfo);

        signableXMLObject.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);

        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);

        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(signableXMLObject);

        try {
            marshaller.marshall(signableXMLObject);
        } catch (MarshallingException e) {
            throw IdentityException.error("Unable to marshall the request", e);
        }

        org.apache.xml.security.Init.init();
        try {
            Signer.signObjects(signatureList);
        } catch (SignatureException e) {
            throw IdentityException.error("Error occurred while signing request", e);
        }

        return signableXMLObject;
    }

    /**
     * Validate the signature of an assertion
     *
     * @param request    SAML Assertion, this could be either a SAML Request or a
     *                   LogoutRequest
     * @param alias      Certificate alias against which the signature is validated.
     * @param domainName domain name of the subject
     * @return true, if the signature is valid.
     */
    public static boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                X509Credential cred = (X509Credential) OpenSAML3Util.getX509CredentialImplForTenant(domainName, alias);


                return OpenSAML3Util.validateXMLSignature(request, cred, alias);
            } catch (IdentitySAML2SSOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature validation failed for the SAML Message : Failed to construct the X509CredentialImpl for the alias " +
                            alias, e);
                }
            } catch (IdentityException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Validation Failed for the SAML Assertion : Signature is invalid.", e);

                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while validating XML signature.", e);
                }
            }
        }
        return isSignatureValid;
    }

    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param tenantDomain
     * @param alias
     * @return X509CredentialImpl object containing the public certificate of
     * that tenant
     * @throws org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException Error when creating X509CredentialImpl object
     */
    public static X509CredentialImpl getX509CredentialImplForTenant(String tenantDomain, String alias)
            throws IdentitySAML2SSOException {

        if (tenantDomain == null || tenantDomain.trim().equals(null) || alias == null || alias.trim().equals(null)) {
            throw new IllegalArgumentException("Invalid parameters; domain name : " + tenantDomain + ", " +
                    "alias : " + alias);
        }
        int tenantId;
        try {
            tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error getting the tenant ID for the tenant domain : " + tenantDomain;
            throw new IdentitySAML2SSOException(errorMsg, e);
        }

        KeyStoreManager keyStoreManager;
        // get an instance of the corresponding Key Store Manager instance
        keyStoreManager = KeyStoreManager.getInstance(tenantId);

        X509CredentialImpl credentialImpl = null;
        KeyStore keyStore;

        try {
            if (tenantId != -1234) {// for tenants, load private key from their generated key store
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
            } else { // for super tenant, load the default pub. cert using the
                // config. in carbon.xml
                keyStore = keyStoreManager.getPrimaryKeyStore();
            }
            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
            credentialImpl = new X509CredentialImpl(cert);

        } catch (Exception e) {
            String errorMsg = "Error instantiating an X509CredentialImpl object for the public certificate of " + tenantDomain;
            throw new IdentitySAML2SSOException(errorMsg, e);
        }
        return credentialImpl;
    }

    public static boolean validateXMLSignature(RequestAbstractType request, X509Credential cred,
                                               String alias) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                SignatureValidationProvider provider = new ApacheSantuarioSignatureValidationProviderImpl();
                provider.validate(request.getSignature(), cred);
                //SignatureValidator validator = new SignatureValidator();
                //validator.validate(request.getSignature(), cred);
                isSignatureValid = true;
            } catch (SignatureException e) {
                e.printStackTrace();
            }
        }
        return isSignatureValid;
    }


}
