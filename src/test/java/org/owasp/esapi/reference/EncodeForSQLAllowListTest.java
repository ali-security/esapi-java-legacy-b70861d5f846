/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2025 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
package org.owasp.esapi.reference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.owasp.esapi.PropNames.ACCEPTED_UNSAFE_METHOD_NAMES;
import static org.owasp.esapi.PropNames.ACCEPTED_UNSAFE_METHODS_JUSTIFICATION;

import org.junit.After;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.DB2Codec;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.OracleCodec;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.errors.NotConfiguredByDefaultException;

/**
 * Regression tests for CVE-2025-5878 (ESAPI Security Bulletin #13).
 * {@code Encoder.encodeForSQL} cannot reliably neutralize SQL special
 * characters (e.g., {@code OracleCodec} never escapes the backslash escape
 * character), so it must refuse to run unless it has been explicitly enabled
 * via the ESAPI property <b>ESAPI.dangerouslyAllowUnsafeMethods.methodNames</b>.
 */
public class EncodeForSQLAllowListTest {

    private static final String ENCODE_FOR_SQL = "org.owasp.esapi.reference.DefaultEncoder.encodeForSQL";

    // Classic Oracle backslash-escape SQLi payload from CVE-2025-5878.
    private static final String ORACLE_SQLI_PAYLOAD = "\\' OR 1=1 --";

    private static final String MISSING = new String("<missing>");

    /** Overrides the allow-list (and justification) properties. */
    private static class AllowListConf extends SecurityConfigurationWrapper {
        private final String methodNames;
        private final String justification;

        AllowListConf(SecurityConfiguration orig, String methodNames, String justification) {
            super(orig);
            this.methodNames = methodNames;
            this.justification = justification;
        }

        @Override
        public String getStringProp(String propName) throws ConfigurationException {
            if ( ACCEPTED_UNSAFE_METHOD_NAMES.equals(propName) ) {
                return valueOrThrow(propName, methodNames);
            }
            if ( ACCEPTED_UNSAFE_METHODS_JUSTIFICATION.equals(propName) ) {
                return valueOrThrow(propName, justification);
            }
            return super.getStringProp(propName);
        }

        private static String valueOrThrow(String propName, String value) {
            if ( value == MISSING ) {
                throw new ConfigurationException("SecurityConfiguration for " + propName + " not found in ESAPI.properties");
            }
            return value;
        }
    }

    @After
    public void tearDown() {
        ESAPI.override(null);
    }

    private static void allowList(String methodNames, String justification) {
        ESAPI.override( new AllowListConf(ESAPI.securityConfiguration(), methodNames, justification) );
    }

    private static void assertEncodeForSQLRefused(Codec codec, String input) {
        Encoder encoder = DefaultEncoder.getInstance();
        try {
            String encoded = encoder.encodeForSQL(codec, input);
            fail("encodeForSQL must not run unless explicitly enabled, but returned: " + encoded);
        } catch (NotConfiguredByDefaultException expected) {
            String msg = expected.getMessage();
            assertTrue(msg, msg.contains(ACCEPTED_UNSAFE_METHOD_NAMES));
            assertTrue(msg, msg.contains(ENCODE_FOR_SQL));
        }
    }

    @Test
    public void testOracleBackslashInjectionRefusedWhenAllowListEmpty() {
        allowList("", "");
        assertEncodeForSQLRefused(new OracleCodec(), ORACLE_SQLI_PAYLOAD);
    }

    @Test
    public void testAllSqlCodecsRefusedWhenAllowListEmpty() {
        allowList("   ", "");
        assertEncodeForSQLRefused(new MySQLCodec(MySQLCodec.Mode.ANSI), "Jeff' or '1'='1");
        assertEncodeForSQLRefused(new MySQLCodec(MySQLCodec.Mode.STANDARD), "Jeff' or '1'='1");
        assertEncodeForSQLRefused(new DB2Codec(), "Jeff' or '1'='1");
        assertEncodeForSQLRefused(new OracleCodec(), ORACLE_SQLI_PAYLOAD);
    }

    @Test
    public void testRefusedWhenAllowListPropertyMissing() {
        allowList(MISSING, MISSING);
        assertEncodeForSQLRefused(new OracleCodec(), ORACLE_SQLI_PAYLOAD);
    }

    @Test
    public void testRefusedEvenForNullInput() {
        allowList("", "");
        assertEncodeForSQLRefused(new OracleCodec(), null);
    }

    @Test
    public void testRefusedWhenOnlySimilarMethodNamesAllowed() {
        allowList("org.owasp.esapi.reference.DefaultEncoder.encodeForSQ," +
                  "org.owasp.esapi.reference.DefaultEncoder.encodeForSQLX," +
                  "org.owasp.esapi.Encoder.encodeForSQL," +
                  "org.owasp.esapi.reference.DefaultEncoder.encodeForHTML", "");
        assertEncodeForSQLRefused(new OracleCodec(), ORACLE_SQLI_PAYLOAD);
    }

    @Test
    public void testExplicitlyEnabledStillEncodes() {
        allowList(" org.owasp.esapi.reference.DefaultEncoder.encodeForHTML , " + ENCODE_FOR_SQL + " ",
                  "Ticket #12345");
        Encoder encoder = DefaultEncoder.getInstance();
        assertEquals("Jeff'' or ''1''=''1", encoder.encodeForSQL(new OracleCodec(), "Jeff' or '1'='1"));
        assertEquals(null, encoder.encodeForSQL(new OracleCodec(), null));
    }

    @Test
    public void testExplicitlyEnabledWithoutJustificationStillEncodes() {
        allowList(ENCODE_FOR_SQL, MISSING);
        Encoder encoder = DefaultEncoder.getInstance();
        assertEquals("Jeff'' or ''1''=''1",
                     encoder.encodeForSQL(new MySQLCodec(MySQLCodec.Mode.ANSI), "Jeff' or '1'='1"));
    }

    @Test
    public void testNotConfiguredByDefaultExceptionIsConfigurationException() {
        NotConfiguredByDefaultException ex = new NotConfiguredByDefaultException((String) null);
        assertTrue(ex instanceof ConfigurationException);
        assertTrue(ex.getMessage().contains("without being explicitly allowed"));
    }
}
