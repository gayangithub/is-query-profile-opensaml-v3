package org.wso2.carbon.identity.saml.profile.query;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;

/**
 * X509Credential implementation for signature verification of self issued tokens. The key is
 * constructed from modulus and exponent
 */
public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private X509Certificate signingCert = null;

    /**
     * The key is constructed form modulus and exponent.
     *
     * @param modulus
     * @param publicExponent
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public X509CredentialImpl(BigInteger modulus, BigInteger publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(spec);
    }

    public X509CredentialImpl(X509Certificate cert) {
        publicKey = cert.getPublicKey();
        signingCert = cert;
    }

    @Nullable
    public String getEntityId() {
        return null;
    }

    @Nullable
    public UsageType getUsageType() {
        return null;
    }

    @Nonnull
    public Collection<String> getKeyNames() {
        return null;
    }

    @Nullable
    public PublicKey getPublicKey() {
        return null;
    }


    @Nullable
    public PrivateKey getPrivateKey() {
        return null;
    }

    @Nullable
    public SecretKey getSecretKey() {
        return null;
    }

    @Nullable
    public CredentialContextSet getCredentialContextSet() {
        return null;
    }

    @Nonnull
    public Class<? extends Credential> getCredentialType() {
        return null;
    }

    public X509Certificate getSigningCert() {
        return signingCert;
    }

    @Nonnull
    public X509Certificate getEntityCertificate() {
        return null;
    }

    @Nonnull
    public Collection<X509Certificate> getEntityCertificateChain() {
        return null;
    }

    @Nullable
    public Collection<X509CRL> getCRLs() {
        return null;
    }

    // ********** Not implemented **************************************************************


}
