package com.github.dcimarc.himaya.security;

import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;

import static org.junit.jupiter.api.Assertions.*;

class HimayaSecurityTest {

    @Test
    void testGetVersion() {
        String version = HimayaSecurity.getVersion();
        assertNotNull(version);
        assertEquals("1.0.0", version);
    }

    @Test
    void testUtilityClassCannotBeInstantiated() {
        Exception exception = assertThrows(Exception.class, () -> {
            // Use reflection to try to instantiate the private constructor
            java.lang.reflect.Constructor<HimayaSecurity> constructor = 
                HimayaSecurity.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            constructor.newInstance();
        });
        
        // The AssertionError should be wrapped in an InvocationTargetException
        assertInstanceOf(InvocationTargetException.class, exception);
        assertInstanceOf(AssertionError.class, exception.getCause());
    }

    @Test
    void testPathHelperFunctionality() {
        // Test that the helper provides access to path traversal protection
        assertTrue(HimayaSecurity.paths().isPathSafe("documents/file.txt"));
        assertFalse(HimayaSecurity.paths().isPathSafe("../../../etc/passwd"));
        
        String sanitized = HimayaSecurity.paths().sanitizePath("../documents/file.txt");
        assertEquals("../documents/file.txt", sanitized); // normalize() preserves leading ..
    }

    @Test
    void testInputHelperFunctionality() {
        // Test that the helper provides access to input validation
        assertTrue(HimayaSecurity.input().isValidEmail("user@example.com"));
        assertFalse(HimayaSecurity.input().isValidEmail("invalid-email"));
        
        assertTrue(HimayaSecurity.input().isAlphanumeric("abc123"));
        assertFalse(HimayaSecurity.input().isAlphanumeric("abc-123"));
        
        assertTrue(HimayaSecurity.input().containsDangerousChars("<script>"));
        assertFalse(HimayaSecurity.input().containsDangerousChars("normal text"));
        
        String sanitized = HimayaSecurity.input().sanitizeInput("<script>alert('xss')</script>");
        assertEquals("", sanitized);
    }

    @Test
    void testHelpersSingleton() {
        // Test that helpers are singletons
        assertSame(HimayaSecurity.paths(), HimayaSecurity.paths());
        assertSame(HimayaSecurity.input(), HimayaSecurity.input());
    }
}