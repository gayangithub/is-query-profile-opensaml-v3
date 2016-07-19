/*
 *
 *  * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *  *
 *  * WSO2 Inc. licenses this file to you under the Apache License,
 *  * Version 2.0 (the "License"); you may not use this file except
 *  * in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing,
 *  * software distributed under the License is distributed on an
 *  * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  * KIND, either express or implied.  See the License for the
 *  * specific language governing permissions and limitations
 *  * under the License.
 *
 */

package org.wso2.carbon.identity.saml.profile.query.dto;


import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class UserDTO {

    private String userName;
    private String tenantDomain;

    public UserDTO(String fullQualifiedUserName){
        this.userName =  MultitenantUtils.getTenantAwareUsername(fullQualifiedUserName);
        this.tenantDomain = MultitenantUtils.getTenantDomain(fullQualifiedUserName);

    }

    /**
     * Sets the username of the user
     *
     * @param userName
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /**
     * Sets the tenant domain of the user
     *
     * @param tenantDomain tenant domain of the user
     */
    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    /**
     * Returns the username of the user
     *
     * @return username
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Returns the tenant domain of the user
     *
     * @return tenant domain
     */
    public String getTenantDomain() {
        return tenantDomain;
    }
}
