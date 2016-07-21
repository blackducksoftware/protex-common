/*******************************************************************************
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package com.blackducksoftware.integration.protex;

import com.blackducksoftware.sdk.fault.ErrorCode;
import com.blackducksoftware.sdk.fault.SdkFault;

public class ProtexFacadeException extends Exception {

    /**
	 * 
	 */
	private static final long serialVersionUID = -2199839116371988123L;

	private ErrorCode sdkFaultErrorCode;

    private String sdkFaultMessage;

    public ProtexFacadeException() {

    }

    public ProtexFacadeException(String message)
    {
        super(message);
    }

    public ProtexFacadeException(Throwable cause)
    {
        super(cause);
        if (cause instanceof SdkFault) {
            SdkFault fault = (SdkFault) cause;
            sdkFaultErrorCode = fault.getFaultInfo().getErrorCode();
            sdkFaultMessage = fault.getFaultInfo().getMessage();
        }
    }

    public ProtexFacadeException(String message, Throwable cause)
    {
        super(message, cause);
        if (cause instanceof SdkFault) {
            SdkFault fault = (SdkFault) cause;
            sdkFaultErrorCode = fault.getFaultInfo().getErrorCode();
            sdkFaultMessage = fault.getFaultInfo().getMessage();
        }
    }

    public ErrorCode getSdkFaultErrorCode() {
        return sdkFaultErrorCode;
    }

    public String getSdkFaultMessage() {
        return sdkFaultMessage;
    }

}
