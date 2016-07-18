/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.saml.profile.query;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;


public class SignKeyDataHolder implements X509Credential {

    final static Log log = LogFactory.getLog(X509Credential.class);
    public static final String SECURITY_KEY_STORE_KEY_ALIAS = "Security.KeyStore.KeyAlias";
    final static Log log = LogFactory.getLog(X509Credential.class);
    private static final String DSA_ENCRYPTION_ALGORITHM = "DSA";
    private String signatureAlgorithm = null;
    private X509Certificate[] issuerCerts = null;

    private PrivateKey issuerPK = null;

    private PublicKey publicKey = null;

    public SignKeyDataHolder(String username) throws IdentityException {
        String keyAlias = null;
        KeyStoreAdmin keyAdmin;
        KeyStoreManager keyMan;
        Certificate[] certificates;
        int tenantID;
        String tenantDomain;
        String userTenantDomain;
        String spTenantDomain;

        try {

            userTenantDomain = MultitenantUtils.getTenantDomain(username);
            spTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

            if (userTenantDomain == null) {
                // all local authenticator must set the value of userTenantDomain.
                // if userTenantDomain is null that means, there is no local authenticator or
                // the assert with local ID is set. In that case, this should be coming from
                // federated authentication. In that case, we treat SP domain is equal to user domain.
                userTenantDomain = spTenantDomain;
            }

            if (!SAMLSSOUtil.isSaaSApplication() && !spTenantDomain.equalsIgnoreCase(userTenantDomain)) {
                throw IdentityException.error("Service Provider tenant domain must be equal to user tenant domain"
                        + " for non-SaaS applications");
            }

            String signWithValue = IdentityUtil.getProperty(
                    SAMLSSOConstants.FileBasedSPConfig.USE_AUTHENTICATED_USER_DOMAIN_CRYPTO);
            if (signWithValue != null && "true".equalsIgnoreCase(signWithValue.trim())) {
                tenantDomain = userTenantDomain;
                tenantID = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            } else {
                tenantDomain = spTenantDomain;
                tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            }

            IdentityTenantUtil.initializeRegistry(tenantID, tenantDomain);

            if (tenantID != MultitenantConstants.SUPER_TENANT_ID) {
                String keyStoreName = SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain);
                keyAlias = tenantDomain;
                keyMan = KeyStoreManager.getInstance(tenantID);
                KeyStore keyStore = keyMan.getKeyStore(keyStoreName);
                issuerPK = (PrivateKey) keyMan.getPrivateKey(keyStoreName, tenantDomain);
                certificates = keyStore.getCertificateChain(keyAlias);
                issuerCerts = new X509Certificate[certificates.length];

                int i = 0;
                for (Certificate certificate : certificates) {
                    issuerCerts[i++] = (X509Certificate) certificate;
                }

                signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;

                publicKey = issuerCerts[0].getPublicKey();
                String pubKeyAlgo = publicKey.getAlgorithm();
                if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
                    signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }

            } else {
                keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                        SECURITY_KEY_STORE_KEY_ALIAS);

                keyAdmin = new KeyStoreAdmin(tenantID,
                        SAMLSSOUtil.getRegistryService().getGovernanceSystemRegistry());
                keyMan = KeyStoreManager.getInstance(tenantID);

                issuerPK = (PrivateKey) keyAdmin.getPrivateKey(keyAlias, true);

                certificates = keyMan.getPrimaryKeyStore().getCertificateChain(keyAlias);

                issuerCerts = new X509Certificate[certificates.length];

                int i = 0;
                for (Certificate certificate : certificates) {
                    issuerCerts[i++] = (X509Certificate) certificate;
                }

                signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;

                publicKey = issuerCerts[0].getPublicKey();
                String pubKeyAlgo = publicKey.getAlgorithm();
                if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
                    signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }
            }

        } catch (IdentityException e) {
            log.error(e);

        } catch (Exception e) {
            log.error(e);

        }

    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }


    @Nullable
    public String getEntityId() {
        return null;
    }

    @Nullable
    public UsageType getUsageType() {
        return null;
    }


    public Collection<String> getKeyNames() {
        return null;
    }

    @Nullable
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Nullable
    public PrivateKey getPrivateKey() {
        return issuerPK;
    }

    @Nullable
    public SecretKey getSecretKey() {
        return null;
    }

    @Nullable
    public CredentialContextSet getCredentialContextSet() {
        return null;
    }


    public Class<? extends Credential> getCredentialType() {
        return null;
    }


    @Nonnull
    public X509Certificate getEntityCertificate() {
        return issuerCerts[0];
    }


    public Collection<X509Certificate> getEntityCertificateChain() {
        return null;
    }

    @Nullable
    public Collection<X509CRL> getCRLs() {
        return null;
    }
}

