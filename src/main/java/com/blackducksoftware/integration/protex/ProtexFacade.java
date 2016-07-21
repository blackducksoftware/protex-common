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

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.transports.http.configuration.ProxyServerType;

import com.blackducksoftware.integration.protex.exceptions.ProtexCredentialsValidationException;
import com.blackducksoftware.integration.protex.sdk.ProtexServerProxy;
import com.blackducksoftware.integration.protex.sdk.exceptions.ServerConfigException;
import com.blackducksoftware.integration.protex.sdk.exceptions.ServerConnectionException;
import com.blackducksoftware.integration.suite.sdk.logging.IntLogger;
import com.blackducksoftware.integration.suite.sdk.logging.LogLevel;
import com.blackducksoftware.sdk.fault.ErrorCode;
import com.blackducksoftware.sdk.fault.SdkFault;
import com.blackducksoftware.sdk.protex.license.LicenseCategory;
import com.blackducksoftware.sdk.protex.obligation.ObligationCategory;
import com.blackducksoftware.sdk.protex.project.AnalysisSourceLocation;
import com.blackducksoftware.sdk.protex.project.AnalysisSourceRepository;
import com.blackducksoftware.sdk.protex.project.CloneOption;
import com.blackducksoftware.sdk.protex.project.Project;
import com.blackducksoftware.sdk.protex.project.ProjectRequest;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeNode;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeNodeRequest;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeNodeType;
import com.blackducksoftware.sdk.protex.project.codetree.NodeCountType;
import com.blackducksoftware.sdk.protex.report.Report;
import com.blackducksoftware.sdk.protex.report.ReportFormat;
import com.blackducksoftware.sdk.protex.report.ReportTemplate;
import com.blackducksoftware.sdk.protex.util.CodeTreeUtilities;

public class ProtexFacade implements Serializable {
    private static final long serialVersionUID = -4294831994164831757L;

    public static final String PROJECT_NAME_TOO_LONG = "Project name should be under \"250\" characters in length.";

    protected ProtexServerProxy serverProxy;

    private IntLogger logger;

    public String serverUrl;

    public ProtexFacade(String serverUrl, String username, String password) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, IOException, ServerConfigException {
        this(serverUrl, username, password, 300L);
    }

    public ProtexFacade(String serverUrl, String username, String encryptedPassword, boolean isPasswordEncrypted) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, IOException, ServerConfigException {
        this(serverUrl, username, encryptedPassword, 300L, isPasswordEncrypted);
    }

    public ProtexFacade(String serverUrl, String username, String password, long timeout) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, IOException, ServerConfigException {
        if (StringUtils.isBlank(serverUrl)) {
            throw new IllegalArgumentException(
                    "Protex server Url was not provided.");
        }
        if (StringUtils.isBlank(username)) {
            throw new IllegalArgumentException(
                    "Protex server Username was not provided.");
        }

        serverProxy = new ProtexServerProxy(serverUrl, username, password, timeout * 1000);
        serverProxy.setUseContextClassLoader(true);

        this.serverUrl = serverUrl;
    }

    public ProtexFacade(String serverUrl, String username, String password, long timeout, boolean isPasswordEncrypted) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, IOException, ServerConfigException {
        if (StringUtils.isBlank(serverUrl)) {
            throw new IllegalArgumentException(
                    "Protex server Url was not provided.");
        }
        if (StringUtils.isBlank(username)) {
            throw new IllegalArgumentException(
                    "Protex server Username was not provided.");
        }

        serverProxy = new ProtexServerProxy(serverUrl, username, password, timeout * 1000, isPasswordEncrypted);
        serverProxy.setUseContextClassLoader(true);

        this.serverUrl = serverUrl;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setLogger(IntLogger logger) {
        this.logger = logger;
        serverProxy.setLogger(logger);
    }

    public void setProxySettings(String proxyName, int proxyPort, ProxyServerType proxyType, Boolean updateApis) {
        this.setProxySettings(proxyName, proxyPort, proxyType, updateApis, null, null);
    }

    public void setProxySettings(String proxyName, int proxyPort, ProxyServerType proxyType, Boolean updateApis, String proxyUsername, String proxyPassword) {
        serverProxy.setProxyServer(proxyName, proxyPort, proxyType, updateApis, proxyUsername, proxyPassword);
    }

    public void validateConnection() throws ServerConfigException,
            ServerConnectionException, ProtexCredentialsValidationException {
        LogLevel originalLogLevel = null;
        try {
            originalLogLevel = logger.getLogLevel();

            logger.setLogLevel(LogLevel.OFF);
            // We turn this logging off so the User doesn't see the SDKFault messages
            // that occur when the User is authenticated

            serverProxy.getProjectApi().getProjectById("fakeProjectId");
            // serverProxy.getUserApi().getUserByEmail("FakeUser@Fake.com");
            // Does not matter if we find the fake user or not
        } catch (SdkFault e) {
            logger.setLogLevel(originalLogLevel);
            if (e.getFaultInfo().getErrorCode() != null) {
                if (e.getFaultInfo().getErrorCode()
                        .equals(ErrorCode.PROJECT_NOT_FOUND)) {
                    // Should not find the user FakeUser@Fake.com
                    logger.info("Validation was successful!");
                } else {
                    logger.error("Validation error: "
                            + e.getFaultInfo().getErrorCode());
                    throw new ProtexCredentialsValidationException(e.getMessage(), e);
                }
            } else {
                logger.error("Validation error: "
                        + e.getFaultInfo().getErrorCode());
                throw new ProtexCredentialsValidationException(e.getMessage(), e);
            }

        } catch (ServerConnectionException e) {
            throw e;
        } finally {
            logger.setLogLevel(originalLogLevel);
        }
    }

    public boolean checkProjectExists(String projectName) throws ServerConfigException, ServerConnectionException, ProtexFacadeException {
        if (StringUtils.isBlank(projectName)) {
            throw new IllegalArgumentException(
                    "Need to provide the name of the Protex Project to be checked.");
        }
        try {
            Project proj = serverProxy.getProjectApi().getProjectByName(projectName);
            if (proj != null) {
                logger.info("The project '" + projectName + "' exists.");
                return true;
            } else {
                return false;
            }
        } catch (SdkFault e) {
            if (e.getFaultInfo() != null
                    && e.getFaultInfo().getErrorCode() != null) {
                if (e.getFaultInfo().getErrorCode().equals(ErrorCode.INVALID_CREDENTIALS)) {
                    throw new ProtexFacadeException("Error checking the project '" + projectName + "' :" + e.getMessage(), e);
                }
                if (e.getFaultInfo().getErrorCode().equals(ErrorCode.PROJECT_NOT_FOUND)) {
                    logger.info("The project '" + projectName + "' does not exist.");
                    return false;
                }
                throw new ProtexFacadeException("Error checking the project '" + projectName + "' : " + e.getMessage(), e);
            } else {
                logger.error(e.getMessage(), e);
                throw new ProtexFacadeException("Error checking the project '" + projectName + "' : " + e.getMessage(), e);
            }
        }
    }

    public String createProtexProject(String projectName,
            String cloneProjectName) throws ProtexFacadeException,
            ServerConfigException, ServerConnectionException, ProtexFacadeException {
        if (StringUtils.isBlank(projectName)) {
            throw new IllegalArgumentException(
                    "Need to provide a name for the Protex Project to be created.");
        }
        if (projectName.length() >= 250) {
            throw new ProtexFacadeException(PROJECT_NAME_TOO_LONG);
        }

        try {

            if (checkProjectExists(projectName)) {
                throw new ProtexFacadeException("The project '" + projectName + "' already exists.");
            }

            if (StringUtils.isBlank(cloneProjectName)) {

                ProjectRequest p = new ProjectRequest();
                p.setName(projectName);
                p.setDescription("Project Created by Protex-CI-Plugin");

                String projectId = null;

                projectId = serverProxy.getProjectApi().createProject(p,
                        LicenseCategory.PROPRIETARY);

                // Check for valid return
                if (projectId == null) {
                    throw new ProtexFacadeException(
                            "Error while creating project " + projectName
                                    + ", No project ID created");
                } else {
                    logger.info("The project '" + projectName + "' has been created.");
                    return projectId;
                }
            } else {

                return cloneProtexProject(projectName, cloneProjectName);
            }

        } catch (SdkFault e) {
            if (e.getFaultInfo() != null
                    && e.getFaultInfo().getErrorCode() != null) {
                logger.error(e.getFaultInfo().getErrorCode().toString(), e);
                throw new ProtexFacadeException("Error while creating project : " + e.getFaultInfo().getErrorCode().toString(), e);
            } else {
                logger.error(e.getMessage(), e);
                throw new ProtexFacadeException("Error while creating project : " + e.getMessage(), e);
            }
        } catch (ServerConnectionException e) {
            throw e;
        }
    }

    public String cloneProtexProject(String projectName, String cloneProjectName)
            throws ProtexFacadeException, ServerConfigException,
            ServerConnectionException {
        if (StringUtils.isBlank(projectName)
                && StringUtils.isBlank(cloneProjectName)) {
            throw new IllegalArgumentException(
                    "Need to provide a name for the Protex Project to be created. And you need to provide the name of the Protex project to clone from.");
        }
        if (StringUtils.isBlank(projectName)) {
            throw new IllegalArgumentException(
                    "Need to provide a name for the Protex Project to be created.");
        }
        if (StringUtils.isBlank(cloneProjectName)) {
            throw new IllegalArgumentException(
                    "Need to provide the name of the Protex project to clone from.");
        }

        try {

            Project project = null;
            String clonedProjectId = null;
            try {
                // PlaceHolder for SDK Calls

                project = serverProxy.getProjectApi().getProjectByName(
                        cloneProjectName);

                if (project == null) {
                    throw new ProtexFacadeException(
                            "Error getProjectByName returned null");

                }

            } catch (SdkFault e) {
                if (e.getFaultInfo() != null
                        && e.getFaultInfo().getErrorCode() != null) {
                    logger.error(e.getFaultInfo().getErrorCode().toString(), e);
                    throw new ProtexFacadeException("Error cloning the specified project : " + e.getFaultInfo().getErrorCode().toString(), e);
                } else {
                    logger.error(e.getMessage(), e);
                    throw new ProtexFacadeException("Error cloning the specified project : " + e.getMessage(), e);
                }
            }

            List<ObligationCategory> resetAllFulfillments = new ArrayList<ObligationCategory>(0);
            List<CloneOption> analysisAndWork = new ArrayList<CloneOption>();
            // Will have same users assigned and all same settings, included
            // analysis results
            analysisAndWork.add(CloneOption.ANALYSIS_RESULTS);
            analysisAndWork.add(CloneOption.COMPLETED_WORK);
            analysisAndWork.add(CloneOption.ASSIGNED_USERS);

            clonedProjectId = serverProxy.getProjectApi().cloneProject(
                    project.getProjectId(), projectName, analysisAndWork, resetAllFulfillments);
            logger.info("The project '" + projectName + "' has been cloned from '" + cloneProjectName + "'.");
            return clonedProjectId;

        } catch (SdkFault e) {
            if (e.getFaultInfo() != null
                    && e.getFaultInfo().getErrorCode() != null) {
                logger.error(e.getFaultInfo().getErrorCode().toString(), e);
                throw new ProtexFacadeException("Error cloning the specified project : " + e.getFaultInfo().getErrorCode().toString(), e);
            } else {
                logger.error(e.getMessage(), e);
                throw new ProtexFacadeException("Error cloning the specified project : " + e.getMessage(), e);
            }
        } catch (ServerConnectionException e) {
            throw e;
        }
    }

    public String getProtexProjectId(String projectName) throws ServerConfigException, ProtexFacadeException, ServerConnectionException {
        if (StringUtils.isBlank(projectName)) {
            throw new IllegalArgumentException(
                    "Need to provide the name of the Protex Project you want the Id of.");
        }
        try {

            Project proj = serverProxy.getProjectApi().getProjectByName(projectName);
            if (proj != null) {
                logger.info("The project '" + projectName + "' exists with Id: " + proj.getProjectId());
                return proj.getProjectId();
            } else {
                return null;
            }
        } catch (SdkFault e) {
            if (e.getFaultInfo() != null
                    && e.getFaultInfo().getErrorCode() != null) {
                if (e.getFaultInfo().getErrorCode().equals(ErrorCode.INVALID_CREDENTIALS)) {
                    throw new ProtexFacadeException("Server credentials were invalid :" + e.getMessage() + ", errorCode : "
                            + e.getFaultInfo().getErrorCode(), e);
                }
                if (e.getFaultInfo().getErrorCode().equals(ErrorCode.PROJECT_NOT_FOUND)) {
                    throw new ProtexFacadeException("Could not find the project '" + projectName + "' : " + e.getMessage() + ", errorCode : "
                            + e.getFaultInfo().getErrorCode(), e);
                }
                throw new ProtexFacadeException("Error checking the project '" + projectName + "' : " + e.getMessage() + ", errorCode : "
                        + e.getFaultInfo().getErrorCode(), e);
            } else {
                logger.error(e.getMessage(), e);
                throw new ProtexFacadeException("Error checking the project '" + projectName + "' : " + e.getMessage(), e);
            }
        } catch (ServerConnectionException e) {
            throw e;
        }
    }

    /**
     * This method updates a Protex project with a new AnalysisSourceLocation
     *
     *
     * @throws ServerConfigException
     * @throws ProtexFacadeException
     * @throws ServerConnectionException
     */
    public void protexPrepScanProject(
            String projectId, String hostname, String protexProjectSourcePath)
            throws ProtexFacadeException, ServerConfigException, ServerConnectionException {

        if (StringUtils.isBlank(projectId)) {
            throw new IllegalArgumentException(
                    "Need to provide the Id of the Protex Project to prep.");
        }
        if (StringUtils.isBlank(hostname)) {
            throw new IllegalArgumentException(
                    "Need to provide the hostname for the AnalysisSourceLocation.");
        }
        if (StringUtils.isBlank(protexProjectSourcePath)) {
            throw new IllegalArgumentException(
                    "Need to provide the source path for the AnalysisSourceLocation.");
        }

        Project project = null;
        AnalysisSourceLocation analysisSourceLocation = new AnalysisSourceLocation();

        try {

            project = serverProxy.getProjectApi().getProjectById(projectId);

            AnalysisSourceLocation currentSourceLocation = project
                    .getAnalysisSourceLocation();
            if (currentSourceLocation == null
                    || currentSourceLocation.getHostname() != hostname
                    || currentSourceLocation.getRepository() != AnalysisSourceRepository.LOCAL_PROXY
                    || currentSourceLocation.getSourcePath() != protexProjectSourcePath) {

                // This update the project to allow local scan

                analysisSourceLocation.setHostname(hostname);
                analysisSourceLocation
                        .setRepository(AnalysisSourceRepository.LOCAL_PROXY);
                analysisSourceLocation
                        .setSourcePath(protexProjectSourcePath);

                ProjectRequest req = new ProjectRequest();
                req.setAnalysisSourceLocation(analysisSourceLocation);

                // Updating the project
                serverProxy.getProjectApi().updateProject(project.getProjectId(), req);
            }

        } catch (SdkFault e) {
            throw new ProtexFacadeException(
                    "Updating the Project's analysis source location failed : "
                            + e.getMessage(), e);
        } catch (ServerConnectionException e) {
            throw e;
        }
    }

    /**
     * Get the code tree of the specified project
     *
     * @throws ServerConfigException
     * @throws ProtexFacadeException
     * @throws ServerConnectionException
     */
    protected List<CodeTreeNode> getCodeTreeNodes(String projectId, NodeCountType countType) throws ProtexFacadeException, ServerConfigException,
            ServerConnectionException {

        if (StringUtils.isBlank(projectId)) {
            throw new IllegalArgumentException(
                    "Need to provide the Id of the Protex Project that you want the code tree nodes for.");
        }

        if (countType == null) {
            throw new IllegalArgumentException(
                    "Need to provide the NodeCountType so you get the correct node count back.");
        }

        List<CodeTreeNode> codeTreeNodes = null;

        try {
            CodeTreeNodeRequest req = new CodeTreeNodeRequest();
            req.getIncludedNodeTypes().addAll(Arrays.asList(CodeTreeNodeType.values()));
            req.getCounts().add(countType);
            req.setDepth(CodeTreeUtilities.SINGLE_NODE);
            req.setIncludeParentNode(true);

            codeTreeNodes = serverProxy.getCodeTreeApi().getCodeTreeNodes(projectId, "/", req);

        } catch (SdkFault e) {
            e.printStackTrace();
            throw new ProtexFacadeException("Getting project code tree nodes failed : " + e.getMessage(),
                    e);

        } catch (ServerConnectionException e) {
            throw e;
        } finally {
            if (codeTreeNodes == null) {
                codeTreeNodes = new ArrayList<CodeTreeNode>();
            }
        }
        return codeTreeNodes;
    }

    /**
     * Get the pending Id count of the specified project
     *
     * @throws ServerConfigException
     * @throws ProtexFacadeException
     * @throws ServerConnectionException
     */
    public long getPendingIds(String projectId) throws ProtexFacadeException, ServerConfigException, ServerConnectionException {

        if (StringUtils.isBlank(projectId)) {
            throw new IllegalArgumentException(
                    "Need to provide the Id of the Protex Project that you want the Pending Id's of.");
        }

        long pendingIds = 0L;

        try {

            List<CodeTreeNode> nodes = getCodeTreeNodes(projectId, NodeCountType.PENDING_ID_ALL);
            if (nodes.size() != 1) {
                throw new ProtexFacadeException("Getting discoveries pending Id file count failed : Expected to get 1 CodeTreeNode, but got : " + nodes.size());
            } else if (nodes.get(0).getNodeCounts().size() != 1) {
                throw new ProtexFacadeException("Getting discoveries pending Id file count failed : Expected to get 1 NodeCount, but got : "
                        + nodes.get(0).getNodeCounts().size());
            } else {
                pendingIds = nodes.get(0).getNodeCounts().get(0).getCount();
            }
            logger.info("File(s) Pending Identification : " + pendingIds);

        } catch (ServerConnectionException e) {
            throw e;
        }
        return pendingIds;
    }

    /**
     * Get the violation count of the sepcified project
     *
     * @throws ServerConfigException
     * @throws ProtexFacadeException
     * @throws ServerConnectionException
     */
    public long getViolationCount(String projectId) throws ProtexFacadeException, ServerConfigException,
            ServerConnectionException {

        if (StringUtils.isBlank(projectId)) {
            throw new IllegalArgumentException(
                    "Need to provide the Id of the Protex Project that you want the Violations count of.");
        }
        long violationCount = 0L;

        try {

            List<CodeTreeNode> nodes = getCodeTreeNodes(projectId, NodeCountType.VIOLATIONS);
            if (nodes.size() != 1) {
                throw new ProtexFacadeException("Expected to get 1 CodeTreeNode, but got : " + nodes.size());
            } else if (nodes.get(0).getNodeCounts().size() != 1) {
                throw new ProtexFacadeException("Expected to get 1 NodeCount, but got : " + nodes.get(0).getNodeCounts().size());
            } else {
                violationCount = nodes.get(0).getNodeCounts().get(0).getCount();
            }

            logger.info("File(s) with Violation : " + violationCount);

        } catch (ProtexFacadeException e) {
            e.printStackTrace();
            throw new ProtexFacadeException("Getting violations file count failed : " + e.getMessage(),
                    e);

        } catch (ServerConnectionException e) {
            throw e;
        }
        return violationCount;
    }

    /**
     * Gets the specified Report template by name.
     *
     * @throws ServerConfigException
     * @throws ProtexFacadeException
     * @throws ServerConnectionException
     */
    public ReportTemplate getReportTemplate(String reportTemplate) throws ProtexFacadeException, ServerConfigException,
            ServerConnectionException {
        if (StringUtils.isBlank(reportTemplate)) {
            throw new IllegalArgumentException(
                    "Need to provide the name of the Report Template you are trying to retrieve.");
        }
        try {
            return serverProxy.getReportApi().getReportTemplateByTitle(reportTemplate);
        } catch (SdkFault e) {
            if (e.getFaultInfo() != null && e.getFaultInfo().getErrorCode() != null && e.getFaultInfo().getErrorCode() == ErrorCode.REPORT_TEMPLATE_NOT_FOUND) {
                throw new ProtexFacadeException(
                        "Could not find the Report Template : "
                                + reportTemplate);
            }

            throw new ProtexFacadeException(
                    "Getting the Report Template failed : "
                            + e.getMessage(), e);
        } catch (ServerConnectionException e) {
            throw e;
        }
    }

    /**
     * Creates the report from the specified template.
     *
     * @throws ServerConfigException
     * @throws ProtexFacadeException
     * @throws ServerConnectionException
     */
    public Report createReportFromTemplate(String projectId, String reportTemplateId, ReportFormat outputFormat, boolean tableOfContents)
            throws ProtexFacadeException, ServerConfigException,
            ServerConnectionException {
        if (StringUtils.isBlank(projectId)) {
            throw new IllegalArgumentException(
                    "Need to provide the Project Id that you want to create this report for.");
        }
        if (StringUtils.isBlank(reportTemplateId)) {
            throw new IllegalArgumentException(
                    "Need to provide the Id of the Report Template you using to create this report.");
        }
        if (outputFormat == null) {
            throw new IllegalArgumentException(
                    "Need to specify the format you would like this report to be.");
        }

        try {
            return serverProxy.getReportApi().generateProjectReport(projectId, reportTemplateId, outputFormat, tableOfContents);

        } catch (SdkFault e) {
            throw new ProtexFacadeException(
                    "Creating the Protex report failed : "
                            + e.getMessage(), e);
        } catch (ServerConnectionException e) {
            throw e;
        }
    }
}
