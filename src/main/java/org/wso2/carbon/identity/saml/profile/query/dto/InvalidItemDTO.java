/*
 *
 *   Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.wso2.carbon.identity.saml.profile.query.dto;


public class InvalidItemDTO {

    private String validationtype;
    private String message;

    /**
     * Constructor
     * @param validationtype
     * @param message
     */
    public InvalidItemDTO(String validationtype, String message) {
        this.message = message;
        this.validationtype = validationtype;

    }

    /**
     *
     * @return String message
     */
    public String getMessage() {

        return message;
    }

    /**
     *
     * @param message
     */
    public void setMessage(String message) {

        this.message = message;
    }

    /**
     *
     * @return String validationetype
     */
    public String getValidationtype() {

        return validationtype;
    }

    /**
     *
     * @param validationtype
     */
    public void setValidationtype(String validationtype) {
        this.validationtype = validationtype;

    }


}
