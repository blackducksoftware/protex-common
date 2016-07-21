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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;

import junit.framework.Assert;

import org.apache.cxf.transports.http.configuration.ProxyServerType;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.blackducksoftware.integration.protex.exceptions.ProtexCredentialsValidationException;
import com.blackducksoftware.integration.protex.sdk.ProtexServerProxy;
import com.blackducksoftware.integration.protex.sdk.exceptions.ServerConnectionException;
import com.blackducksoftware.integration.protex.util.TestHelper;
import com.blackducksoftware.integration.protex.util.TestLogger;
import com.blackducksoftware.sdk.protex.report.Report;
import com.blackducksoftware.sdk.protex.report.ReportFormat;
import com.blackducksoftware.sdk.protex.report.ReportTemplate;

public class ProtexFacadeTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static File passwordFile;

    private static Properties testProperties;

    private static TestHelper helper;

    @BeforeClass
    public static void init() throws Exception {
        testProperties = new Properties();
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream is = classLoader.getResourceAsStream("test.properties");

        URL passFileResourceUrl = classLoader.getResource("encryptedPasswordFile.txt");

        passwordFile = new File(passFileResourceUrl.toURI());

        try {
            testProperties.load(is);

        } catch (IOException e) {
            System.err.println("reading test.properties failed!");
        }

        TestLogger logger = new TestLogger();
        helper = new TestHelper(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        helper.setLogger(logger);

        try {
            System.out.println("CREATING THE PROJECT : " + testProperties.getProperty("TEST_PROJECT_NAME"));
            helper.createProtexProject(testProperties.getProperty("TEST_PROJECT_NAME"), null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @AfterClass
    public static void tearDown() {
        try {
            helper.deleteProject(testProperties.getProperty("TEST_PROJECT_NAME"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testFacadeCreationNoServer() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Protex server Url was not provided.");
        new ProtexFacade(null, testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
    }

    @Test
    public void testFacadeCreationNoUserName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Protex server Username was not provided.");
        new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), null,
                testProperties.getProperty("TEST_PASSWORD"));
    }

    @Test
    public void testFacadeCreationNoPassword() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Did not provide a valid Protex Password.");
        new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                null);
    }

    @Test
    public void testFacadeCreationEncryptedPassword() throws Exception {
        try {
            System.setProperty(ProtexServerProxy.ENCRYPTED_PASSWORD_FILE, passwordFile.getCanonicalPath());
            new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                    null);
        } finally {
            System.setProperty(ProtexServerProxy.ENCRYPTED_PASSWORD_FILE, "");
        }
    }

    @Test
    public void testFacadeCreationEncryptedPasswordFileFake() throws Exception {
        try {
            exception.expect(IllegalArgumentException.class);
            exception.expectMessage("The password file does not exist at : ");
            System.setProperty(ProtexServerProxy.ENCRYPTED_PASSWORD_FILE, "/FAKEPATH/SHOULDNOTEXIST/SHOULDNOTBE/AFILEHERE");
            new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                    null);
        } finally {
            System.setProperty(ProtexServerProxy.ENCRYPTED_PASSWORD_FILE, "");
        }
    }

    @Test
    public void testFacadeCreation() throws Exception {
        assertNotNull(new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD")));
    }

    @Test
    public void testFacadeCreationWithTimeOut() throws Exception {
        assertNotNull(new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"), 300L));
    }

    @Test
    public void testFacadeValidateConnectionInvalidUrl() throws Exception {
        exception.expect(MalformedURLException.class);
        exception.expectMessage("no protocol: THISISNOTAURL");
        ProtexFacade facade = new ProtexFacade("THISISNOTAURL", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.validateConnection();
    }

    @Test
    public void testFacadeValidateConnectionUnknownUrl() throws Exception {
        exception.expect(ServerConnectionException.class);
        exception.expectMessage("java.net.UnknownHostException: EXAMPLE");
        TestLogger logger = new TestLogger();

        ProtexFacade facade = new ProtexFacade("http://EXAMPLE", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.validateConnection();
    }

    @Test
    public void testFacadeValidateConnectionBadUserNameFormat() throws Exception {
        exception.expect(ProtexCredentialsValidationException.class);
        exception.expectMessage("The user name or password provided was not valid.");
        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), "NOTANEMAIL",
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.validateConnection();
    }

    @Test
    public void testFacadeValidateConnectionBadPassword() throws Exception {
        exception.expect(ProtexCredentialsValidationException.class);
        exception.expectMessage("The user name or password provided was not valid.");
        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                "WRONGPASSWORD");
        facade.setLogger(logger);
        facade.validateConnection();
    }

    @Test
    public void testFacadeValidateConnection() throws Exception {

        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.validateConnection();
        String output = logger.getOutputString();

        assertTrue(output, output.contains("Retrieving Api of class :"));
        assertTrue(output, output.contains("Executing method :"));
        assertTrue(output, output.contains("With input parameters :"));
        assertTrue(output, output.contains("SDKFAULT"));
        assertTrue(output, output.contains("Execution time of method"));
        assertTrue(output, output.contains("Validation was successful!"));
    }

    @Test
    public void testFacadeValidateConnectionPassThroughProxy() throws Exception {

        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL_REQUIRES_PROXY"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.setProxySettings(testProperties.getProperty("TEST_PROXY_HOST_PASSTHROUGH"),
                Integer.valueOf(testProperties.getProperty("TEST_PROXY_PORT_PASSTHROUGH")),
                ProxyServerType.HTTP, false);

        facade.validateConnection();
        String output = logger.getOutputString();

        assertTrue(output, output.contains("Retrieving Api of class :"));
        assertTrue(output, output.contains("Executing method :"));
        assertTrue(output, output.contains("set proxy server for service"));
        assertTrue(output, output.contains("With input parameters :"));
        assertTrue(output, output.contains("SDKFAULT"));
        assertTrue(output, output.contains("Execution time of method"));
        assertTrue(output, output.contains("Validation was successful!"));
    }

    @Test
    public void testFacadeValidateConnectionBasicProxy() throws Exception {

        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL_REQUIRES_PROXY"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.setProxySettings(testProperties.getProperty("TEST_PROXY_HOST_BASIC"),
                Integer.valueOf(testProperties.getProperty("TEST_PROXY_PORT_BASIC")),
                ProxyServerType.HTTP, false,
                testProperties.getProperty("TEST_PROXY_USER_BASIC"),
                testProperties.getProperty("TEST_PROXY_PASSWORD_BASIC"));

        facade.validateConnection();
        String output = logger.getOutputString();

        assertTrue(output, output.contains("Retrieving Api of class :"));
        assertTrue(output, output.contains("Executing method :"));
        assertTrue(output, output.contains("set proxy server for service"));
        assertTrue(output, output.contains("Proxy User : "));
        assertTrue(output, output.contains("With input parameters :"));
        assertTrue(output, output.contains("SDKFAULT"));
        assertTrue(output, output.contains("Execution time of method"));
        assertTrue(output, output.contains("Validation was successful!"));
    }

    // We do not support digest proxy authentication yet becasue CXF cant handle it see
    // https://issues.apache.org/jira/browse/CXF-6551
    // @Test
    // public void testFacadeValidateConnectionDigestProxy() throws Exception {
    //
    // TestLogger logger = new TestLogger();
    // ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL_REQUIRES_PROXY"),
    // testProperties.getProperty("TEST_USERNAME"),
    // testProperties.getProperty("TEST_PASSWORD"));
    // facade.setLogger(logger);
    // facade.setProxySettings(testProperties.getProperty("TEST_PROXY_HOST_DIGEST"),
    // Integer.valueOf(testProperties.getProperty("TEST_PROXY_PORT_DIGEST")),
    // ProxyServerType.HTTP, false,
    // testProperties.getProperty("TEST_PROXY_USER_DIGEST"),
    // testProperties.getProperty("TEST_PROXY_PASSWORD_DIGEST"));
    // facade.validateConnection();
    //
    // String output = logger.getOutputString();
    //
    // assertTrue(output, output.contains("Retrieving Api of class :"));
    // assertTrue(output, output.contains("Executing method :"));
    // assertTrue(output, output.contains("set proxy server for service"));
    // assertTrue(output, output.contains("Proxy User : "));
    // assertTrue(output, output.contains("With input parameters :"));
    // assertTrue(output, output.contains("SDKFAULT"));
    // assertTrue(output, output.contains("Execution time of method"));
    // assertTrue(output, output.contains("Validation was successful!"));
    // }

    @Test
    public void testFacadeCheckProjectExistsInvalidUrl() throws Exception {
        exception.expect(MalformedURLException.class);
        exception.expectMessage("no protocol: THISISNOTAURL");
        ProtexFacade facade = new ProtexFacade("THISISNOTAURL", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.checkProjectExists(testProperties.getProperty("TEST_PROJECT_NAME"));
    }

    @Test
    public void testFacadeCheckProjectExistsUnknownUrl() throws Exception {
        exception.expect(ServerConnectionException.class);
        exception.expectMessage("java.net.UnknownHostException: EXAMPLE");
        ProtexFacade facade = new ProtexFacade("http://EXAMPLE", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.checkProjectExists(testProperties.getProperty("TEST_PROJECT_NAME"));
    }

    @Test
    public void testFacadeCheckProjectExistsBadUserNameFormat() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error checking the project '" + testProperties.getProperty("TEST_PROJECT_NAME")
                + "' :The user name or password provided was not valid.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), "NOTANEMAIL",
                testProperties.getProperty("TEST_PASSWORD"));
        facade.checkProjectExists(testProperties.getProperty("TEST_PROJECT_NAME"));
    }

    @Test
    public void testFacadeCheckProjectExistsBadPassword() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error checking the project '" + testProperties.getProperty("TEST_PROJECT_NAME")
                + "' :The user name or password provided was not valid.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                "WRONGPASSWORD");
        facade.checkProjectExists(testProperties.getProperty("TEST_PROJECT_NAME"));
    }

    @Test
    public void testFacadeCheckProjectExists() throws Exception {

        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);

        facade.checkProjectExists(testProperties.getProperty("TEST_PROJECT_NAME"));

        String output = logger.getOutputString();

        assertTrue(output, output.contains("The project '" + testProperties.getProperty("TEST_PROJECT_NAME") + "' exists."));

    }

    @Test
    public void testFacadeCheckProjectExistsProjectDoesNotExist() throws Exception {

        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.setLogger(logger);

        facade.checkProjectExists("THISPROJECTSHOULDNOTEXIST");

        String output = logger.getOutputString();

        assertTrue(output, output.contains("The project 'THISPROJECTSHOULDNOTEXIST' does not exist."));
    }

    @Test
    public void testFacadeCreateProtexProjectInvalidUrl() throws Exception {
        exception.expect(MalformedURLException.class);
        exception.expectMessage("no protocol: THISISNOTAURL");
        ProtexFacade facade = new ProtexFacade("THISISNOTAURL", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.createProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), null);
    }

    @Test
    public void testFacadeCreateProtexProjectUnknownUrl() throws Exception {
        exception.expect(ServerConnectionException.class);
        exception.expectMessage("java.net.UnknownHostException: EXAMPLE");
        ProtexFacade facade = new ProtexFacade("http://EXAMPLE", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.createProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), null);
    }

    @Test
    public void testFacadeCreateProtexProjectBadUserNameFormat() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error checking the project '" + testProperties.getProperty("TEST_PROJECT_CREATION_NAME")
                + "' :The user name or password provided was not valid.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), "NOTANEMAIL",
                testProperties.getProperty("TEST_PASSWORD"));
        facade.createProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), null);
    }

    @Test
    public void testFacadeCreateProtexProjectBadPassword() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error checking the project '" + testProperties.getProperty("TEST_PROJECT_CREATION_NAME")
                + "' :The user name or password provided was not valid.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                "WRONGPASSWORD");
        facade.createProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), null);
    }

    @Test
    public void testFacadeCreateProtexProjectNoProjectName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide a name for the Protex Project to be created.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.createProtexProject(null, null);
    }

    @Test
    public void testFacadeCreateProtexProjectNameTooLong() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage(ProtexFacade.PROJECT_NAME_TOO_LONG);
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(new TestLogger());

        facade.createProtexProject(
                "BEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIME"
                        + "BEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIM"
                        + "EFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYN"
                        + "IGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDA"
                        + "YNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYB"
                        + "EERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAYBEERTIMEBEERTIMEFRIDAYNIGHTFRIDAYNIGHTYAY",
                null);
    }

    @Test
    public void testFacadeCreateProtexProject() throws Exception {
        TestLogger logger = null;
        try {
            logger = new TestLogger();
            ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                    testProperties.getProperty("TEST_PASSWORD"));

            facade.setLogger(logger);

            assertNotNull(facade.createProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), null));

            String output = logger.getOutputString();

            assertTrue(output, output.contains("The project '" + testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "' does not exist."));
            assertTrue(output, output.contains("The project '" + testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "' has been created."));

        } finally {
            try {
                helper.deleteProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"));
            } catch (Exception e) {
                e.printStackTrace();
            }
            assertTrue(logger.getErrorOutputString().length() == 0);

        }
    }

    @Test
    public void testFacadeCreateProtexProjectCloneProject() throws Exception {
        TestLogger logger = null;

        try {
            logger = new TestLogger();
            ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                    testProperties.getProperty("TEST_PASSWORD"));

            facade.setLogger(logger);

            assertNotNull(facade.createProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"),
                    testProperties.getProperty("TEST_PROJECT_NAME")));

            String output = logger.getOutputString();

            assertTrue(output, output.contains("The project '" + testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "' does not exist."));
            assertTrue(output, output.contains("The project '" + testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "' has been cloned from '"
                    + testProperties.getProperty("TEST_PROJECT_NAME") + "'."));

        } finally {
            try {
                helper.deleteProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"));
            } catch (Exception e) {
                e.printStackTrace();
            }
            assertTrue(logger.getErrorOutputString().length() == 0);
        }
    }

    @Test
    public void testFacadeCloneProtexProjectInvalidUrl() throws Exception {
        exception.expect(MalformedURLException.class);
        exception.expectMessage("no protocol: THISISNOTAURL");
        ProtexFacade facade = new ProtexFacade("THISISNOTAURL", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.cloneProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "2");
    }

    @Test
    public void testFacadeCloneProtexProjectUnknownUrl() throws Exception {
        exception.expect(ServerConnectionException.class);
        exception.expectMessage("java.net.UnknownHostException: EXAMPLE");
        ProtexFacade facade = new ProtexFacade("http://EXAMPLE", testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.cloneProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "2");
    }

    @Test
    public void testFacadeCloneProtexProjectBadUserNameFormat() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error cloning the specified project : INVALID_CREDENTIALS");
        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), "NOTANEMAIL",
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.cloneProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "2");
    }

    @Test
    public void testFacadeCloneProtexProjectBadPassword() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error cloning the specified project : INVALID_CREDENTIALS");
        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                "WRONGPASSWORD");
        facade.setLogger(logger);
        facade.cloneProtexProject(testProperties.getProperty("TEST_PROJECT_CREATION_NAME"), testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "2");
    }

    @Test
    public void testFacadeCloneProtexProjectNoProjectNameOrCloneProjectName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception
                .expectMessage("Need to provide a name for the Protex Project to be created. And you need to provide the name of the Protex project to clone from.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.cloneProtexProject(null, null);
    }

    @Test
    public void testFacadeCloneProtexProjectNoProjectName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide a name for the Protex Project to be created.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.cloneProtexProject(null, testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "2");
    }

    @Test
    public void testFacadeCloneProtexProjectNoCloneProjectName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the name of the Protex project to clone from.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.cloneProtexProject(testProperties.getProperty("TEST_PASSWORD"), null);
    }

    @Test
    public void testFacadeCloneProtexProjectCloneNotExisiting() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Error cloning the specified project : PROJECT_NOT_FOUND");
        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);
        facade.cloneProtexProject(testProperties.getProperty("TEST_PROJECT_CLONE_NAME"),
                testProperties.getProperty("TEST_PROJECT_CREATION_NAME") + "2");

    }

    @Test
    public void testFacadeCloneProtexProjectCloneProject() throws Exception {
        TestLogger logger = null;

        try {
            logger = new TestLogger();
            ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                    testProperties.getProperty("TEST_PASSWORD"));

            facade.setLogger(logger);

            assertNotNull(facade.cloneProtexProject(testProperties.getProperty("TEST_PROJECT_CLONE_NAME"),
                    testProperties.getProperty("TEST_PROJECT_NAME")));

            String output = logger.getOutputString();

            assertTrue(output, output.contains("The project '" + testProperties.getProperty("TEST_PROJECT_CLONE_NAME") + "' has been cloned from '"
                    + testProperties.getProperty("TEST_PROJECT_NAME") + "'."));

        } finally {
            try {
                helper.deleteProject(testProperties.getProperty("TEST_PROJECT_CLONE_NAME"));
            } catch (Exception e) {
                e.printStackTrace();
            }
            assertTrue(logger.getErrorOutputString(), logger.getErrorOutputString().length() == 0);
        }

    }

    @Test
    public void testFacadeGetProjectIdNullName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the name of the Protex Project you want the Id of.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getProtexProjectId(null);

    }

    @Test
    public void testFacadeGetProjectIdEmptyName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the name of the Protex Project you want the Id of.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getProtexProjectId("");

    }

    @Test
    public void testFacadeGetProjectIdNotExistingName() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Could not find the project");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getProtexProjectId("THISPROJECTSHOULDNOTEXIST");
    }

    @Test
    public void testFacadeGetProjectIdExisting() throws Exception {
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        TestLogger logger = new TestLogger();
        facade.setLogger(logger);
        String id = facade.getProtexProjectId(testProperties.getProperty("TEST_PROJECT_NAME"));
        Assert.assertNotNull(id);
    }

    @Test
    public void testFacadeProtexPrepScanProjectNullId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Protex Project to prep.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.protexPrepScanProject(null, "fakeHost", "fakePath");
    }

    @Test
    public void testFacadeProtexPrepScanProjectNullHostName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the hostname for the AnalysisSourceLocation.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.protexPrepScanProject("fakeId", null, "fakePath");
    }

    @Test
    public void testFacadeProtexPrepScanProjectNullSourcePath() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the source path for the AnalysisSourceLocation.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.protexPrepScanProject("fakeId", "fakeHostName", null);
    }

    @Test
    public void testFacadeProtexPrepScanProjectEmptyId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Protex Project to prep.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.protexPrepScanProject("", "fakeHost", "fakePath");
    }

    @Test
    public void testFacadeProtexPrepScanProjectEmptyHostName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the hostname for the AnalysisSourceLocation.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.protexPrepScanProject("fakeId", "", "fakePath");
    }

    @Test
    public void testFacadeProtexPrepScanProjectEmptySourcePath() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the source path for the AnalysisSourceLocation.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.protexPrepScanProject("fakeId", "fakeHostName", "");
    }

    @Test
    public void testFacadeProtexPrepScanProjectNotExistingId() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Updating the Project's analysis source location failed : Could not find project \"madeUpProjectId\".");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        String hostName = InetAddress.getLocalHost().getHostName();
        facade.protexPrepScanProject("madeUpProjectId", hostName, ProtexFacadeTest.class.getProtectionDomain().getCodeSource().getLocation().getFile());
    }

    @Test
    public void testFacadeProtexPrepScanProject() throws Exception {
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"), testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        TestLogger logger = new TestLogger();
        facade.setLogger(logger);
        String id = facade.getProtexProjectId(testProperties.getProperty("TEST_PROJECT_NAME"));
        String hostName = InetAddress.getLocalHost().getHostName();
        facade.protexPrepScanProject(id, hostName, ProtexFacadeTest.class.getProtectionDomain().getCodeSource().getLocation().getFile());
    }

    @Test
    public void testFacadeGetPendingIdsNullProtexId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Protex Project that you want the Pending Id's of.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.getPendingIds(null);
    }

    @Test
    public void testFacadeGetPendingIdsEmptyProtexId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Protex Project that you want the Pending Id's of.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getPendingIds("");
    }

    @Test
    public void testFacadeGetPendingIdsfakeProjectId() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Getting project code tree nodes failed :");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.getPendingIds("fakeProjectId");
    }

    @Test
    public void testFacadeGetPendingIds() throws Exception {
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        TestLogger logger = new TestLogger();
        facade.setLogger(logger);
        String id = facade.getProtexProjectId(testProperties.getProperty("TEST_PROJECT_NAME_SCANNED"));
        String hostName = InetAddress.getLocalHost().getHostName();
        facade.protexPrepScanProject(id, hostName,
                ProtexFacadeTest.class.getProtectionDomain().getCodeSource().getLocation().getFile());

        assertEquals(Long.valueOf(0L), Long.valueOf(facade.getPendingIds(id)));
    }

    @Test
    public void testFacadeGetViolationCountNullProtexId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Protex Project that you want the Violations count of.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.getViolationCount(null);
    }

    @Test
    public void testFacadeGetViolationCountEmptyProtexId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Protex Project that you want the Violations count of.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getViolationCount("");
    }

    @Test
    public void testFacadeetViolationCountfakeProjectId() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Getting project code tree nodes failed :");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.getViolationCount("fakeProjectId");
    }

    @Test
    public void testFacadeGetViolationCount() throws Exception {
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        TestLogger logger = new TestLogger();
        facade.setLogger(logger);
        String id = facade.getProtexProjectId(testProperties.getProperty("TEST_PROJECT_NAME_SCANNED"));
        String hostName = InetAddress.getLocalHost().getHostName();
        facade.protexPrepScanProject(id, hostName,
                ProtexFacadeTest.class.getProtectionDomain().getCodeSource().getLocation().getFile());

        assertEquals(Long.valueOf(0L), Long.valueOf(facade.getViolationCount(id)));

    }

    @Test
    public void testFacadeGetReportTemplateNullTemplateName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the name of the Report Template you are trying to retrieve.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getReportTemplate(null);
    }

    @Test
    public void testFacadeGetReportTemplateEmptyTemplateName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the name of the Report Template you are trying to retrieve.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getReportTemplate("   ");
    }

    @Test
    public void testFacadeGetReportTemplateInvalidTemplateName() throws Exception {
        exception.expect(ProtexFacadeException.class);
        exception.expectMessage("Could not find the Report Template : ASSERTFAKETEMPLATE");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.getReportTemplate("ASSERTFAKETEMPLATE");
    }

    @Test
    public void testFacadeGetReportTemplateValidTemplateName() throws Exception {
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        ReportTemplate template = facade.getReportTemplate(testProperties.getProperty("TEST_REPORT_TEMPLATE"));
        assertNotNull(template);
    }

    @Test
    public void testFacadeCreateReportFromTemplateNullProjectId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Project Id that you want to create this report for.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.createReportFromTemplate(null, null, null, false);
    }

    @Test
    public void testFacadeCreateReportFromTemplateEmptyProjectId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Project Id that you want to create this report for.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.createReportFromTemplate("  ", null, null, false);
    }

    @Test
    public void testFacadeCreateReportFromTemplateNullReportId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Report Template you using to create this report.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.createReportFromTemplate("test", null, null, false);
    }

    @Test
    public void testFacadeCreateReportFromTemplateEmptyReportId() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to provide the Id of the Report Template you using to create this report.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.createReportFromTemplate("test", "  ", null, false);
    }

    @Test
    public void testFacadeCreateReportFromTemplateNullReportFormat() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Need to specify the format you would like this report to be.");
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));

        facade.createReportFromTemplate("test", "test", null, false);
    }

    @Test
    public void testFacadeCreateReportFromTemplateValid() throws Exception {
        TestLogger logger = new TestLogger();
        ProtexFacade facade = new ProtexFacade(testProperties.getProperty("TEST_PROTEX_SERVER_URL"),
                testProperties.getProperty("TEST_USERNAME"),
                testProperties.getProperty("TEST_PASSWORD"));
        facade.setLogger(logger);

        String projectId = facade.getProtexProjectId(testProperties.getProperty("TEST_PROJECT_NAME"));
        ReportTemplate template = facade.getReportTemplate(testProperties.getProperty("TEST_REPORT_TEMPLATE"));

        Report report = facade.createReportFromTemplate(projectId, template.getReportTemplateId(), ReportFormat.HTML, false);
        assertNotNull(report);
    }
}
