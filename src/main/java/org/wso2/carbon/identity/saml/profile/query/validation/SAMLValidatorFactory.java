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

package org.wso2.carbon.identity.saml.profile.query.validation;

import org.opensaml.saml.saml1.core.AuthenticationQuery;
import org.opensaml.saml.saml1.core.AuthorizationDecisionQuery;
import org.opensaml.saml.saml2.core.AssertionIDRequest;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.SubjectQuery;


public class SAMLValidatorFactory {

    public static SAMLQueryValidator getValidator(RequestAbstractType request) {


        SAMLQueryValidator samlQueryValidator = null;

        if (request instanceof AssertionIDRequest) {

            samlQueryValidator = new SAMLIDRequestValidator();

        } else if (request instanceof AttributeQuery) {

            samlQueryValidator = new SAMLAttributeQueryValidator();


        } else if (request instanceof AuthenticationQuery) {

            samlQueryValidator = new SAMLAuthQueryValidator();


        } else if (request instanceof AuthorizationDecisionQuery) {

            samlQueryValidator = new SAMLAuthzDecisionValidator();

        } else if (request instanceof SubjectQuery) {

            samlQueryValidator = new SAMLSubjectQueryValidator();


        }

        return samlQueryValidator;
    }
}
