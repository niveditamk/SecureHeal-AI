// =============================================================================
// WARNING: INTENTIONAL VULNERABILITY — CWE-798 (Hardcoded Credentials)
// =============================================================================
package com.secureheal.target.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    // VULNERABLE: CWE-798 — Hard-coded credentials in source code
    public static final String DB_USERNAME = "admin";
    public static final String DB_PASSWORD = "SuperSecret123!";
    public static final String API_SECRET_KEY = "hardcoded-jwt-secret-key-12345";
    public static final String ENCRYPTION_KEY = "AES256-static-key-do-not-use";
}
