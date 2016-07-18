/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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

package org.wso2.carbon.identity.saml.profile.query.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectQuery;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.saml.profile.query.QueryResponseBuilder;
import org.wso2.carbon.identity.saml.profile.query.handler.SAMLAttributeFinder;
import org.wso2.carbon.identity.saml.profile.query.handler.UserStoreAttributeFinder;
import org.wso2.carbon.identity.saml.profile.query.util.SAMLQueryRequestUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class SAMLSubjectQueryProcessor implements SAMLQueryProcessor {

    final static Log log = LogFactory.getLog(SAMLSubjectQueryProcessor.class);


    /**
     * method to generate response object according to subject
     *
     * @param request
     * @return Response container of one or more assertions
     */
    public Response process(RequestAbstractType request) {

        SubjectQuery query = (SubjectQuery) request;
        String issuer = getIssuer(query.getIssuer());
        String userName = getUserName(query.getSubject());
        Object issuerConfig = getIssuerConfig(issuer);
        Map<String, String> attributes = getUserAttributes(userName, null, issuerConfig);
        Assertion assertion = build(userName, issuerConfig, attributes);
        Assertion[] assertions = {assertion};
        Response response = null;

        try {
            //building response object
            response = QueryResponseBuilder.build(assertions, (SAMLSSOServiceProviderDO) issuerConfig, userName);
            log.info("SAMLSubjectQueryProcessor : response generated");
        } catch (IdentityException e) {
            e.printStackTrace();
        }

        return response;
    }

    /**
     * method to load issuer config
     *
     * @param issuer
     * @return get issuer config object
     */
    protected Object getIssuerConfig(String issuer) {

        try {
            return SAMLQueryRequestUtil.getServiceProviderConfig(issuer);
        } catch (IdentityException e) {
            e.printStackTrace();
        }
        return new Object();
    }

    /**
     * method to load user attributes as map with filtering(AttributeQuery)
     *
     * @param userName
     * @param attributes
     * @param issuerConfig
     * @return Map
     */
    protected Map<String, String> getUserAttributes(String userName, String[] attributes,
                                                    Object issuerConfig) {

        List<SAMLAttributeFinder> finders = getAttributeFinders();

        for (SAMLAttributeFinder finder : finders) {
            Map<String, String> attributeMap = finder.getAttributes(userName, attributes);
            if (attributeMap != null && attributeMap.size() > 0) {
                //filter attributes based on attribute query here
                return attributeMap;
            }
        }

        return new HashMap<String, String>();
    }

    /**
     * build assertion
     *
     * @param userName
     * @param issuer
     * @param attributes
     * @return
     */
    protected Assertion build(String userName, Object issuer, Map<String, String> attributes) {
        Assertion responseAssertion = null;
        try {
            responseAssertion = SAMLQueryRequestUtil.buildSAMLAssertion(userName, attributes, (SAMLSSOServiceProviderDO) issuer);
        } catch (IdentityException e) {
            e.printStackTrace();
        }
        return responseAssertion;
    }

    /**
     * get issuer value
     *
     * @param issuer
     * @return
     */
    protected String getIssuer(Issuer issuer) {

        return issuer.getValue();
    }

    /**
     * get subject value
     *
     * @param subject
     * @return String subject vslue
     */
    protected String getUserName(Subject subject) {

        return subject.getNameID().getValue();
    }

    /**
     * method to select attribute finder source
     *
     * @return List
     */
    private List<SAMLAttributeFinder> getAttributeFinders() {

        List<SAMLAttributeFinder> finders = new ArrayList<SAMLAttributeFinder>();
        finders.add(new UserStoreAttributeFinder());
        return finders;
    }
}
