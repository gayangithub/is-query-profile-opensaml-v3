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

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.identity.saml.profile.query.handler.SAMLAssertionFinder;

import java.util.ArrayList;
import java.util.List;


public class SAMLIDRequestProcessor implements SAMLQueryProcessor {
    /**
     * implemetation of process method for requesting existing assertion
     *
     * @param request
     * @return
     */
    public Response process(RequestAbstractType request) {

        String id = getId(request);
        Response response = null;
        List<SAMLAssertionFinder> finders = getFinders();

        for (SAMLAssertionFinder finder : finders) {
            Assertion[] assertions = finder.find(id);
            if (assertions != null && assertions.length > 0) {
                return response;
            }
        }

        return response;
    }

    /**
     * method to select Assertion finders
     *
     * @return List
     */
    private List<SAMLAssertionFinder> getFinders() {

        return new ArrayList<SAMLAssertionFinder>();
    }

    /**
     * method to get Request ID
     *
     * @param request
     * @return
     */
    private String getId(RequestAbstractType request) {

        return request.getID();
    }


}
