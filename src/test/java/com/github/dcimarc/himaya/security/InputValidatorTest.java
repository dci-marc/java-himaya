package com.github.dcimarc.himaya.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InputValidatorTest {

    @Test
    void testIsValidEmail_WithValidEmails() {
        assertTrue(InputValidator.isValidEmail("user@example.com"));
        assertTrue(InputValidator.isValidEmail("test.email@domain.org"));
        assertTrue(InputValidator.isValidEmail("user123@test-domain.co.uk"));
    }

    @Test
    void testIsValidEmail_WithInvalidEmails() {
        assertFalse(InputValidator.isValidEmail("invalid-email"));
        assertFalse(InputValidator.isValidEmail("@domain.com"));
        assertFalse(InputValidator.isValidEmail("user@"));
        assertFalse(InputValidator.isValidEmail("user@domain"));
        assertFalse(InputValidator.isValidEmail(""));
        assertFalse(InputValidator.isValidEmail(null));
    }

    @Test
    void testIsAlphanumeric() {
        assertTrue(InputValidator.isAlphanumeric("abc123"));
        assertTrue(InputValidator.isAlphanumeric("ABC"));
        assertTrue(InputValidator.isAlphanumeric("123"));
        assertTrue(InputValidator.isAlphanumeric("userABC123"));
        
        assertFalse(InputValidator.isAlphanumeric("abc-123"));
        assertFalse(InputValidator.isAlphanumeric("abc 123"));
        assertFalse(InputValidator.isAlphanumeric("abc@123"));
        assertFalse(InputValidator.isAlphanumeric(""));
        assertFalse(InputValidator.isAlphanumeric(null));
    }

    @Test
    void testIsAlphabetic() {
        assertTrue(InputValidator.isAlphabetic("abc"));
        assertTrue(InputValidator.isAlphabetic("ABC"));
        assertTrue(InputValidator.isAlphabetic("AbCdEf"));
        
        assertFalse(InputValidator.isAlphabetic("abc123"));
        assertFalse(InputValidator.isAlphabetic("abc-def"));
        assertFalse(InputValidator.isAlphabetic(""));
        assertFalse(InputValidator.isAlphabetic(null));
    }

    @Test
    void testIsNumeric() {
        assertTrue(InputValidator.isNumeric("123"));
        assertTrue(InputValidator.isNumeric("0"));
        assertTrue(InputValidator.isNumeric("999999"));
        
        assertFalse(InputValidator.isNumeric("123.45"));
        assertFalse(InputValidator.isNumeric("123abc"));
        assertFalse(InputValidator.isNumeric(""));
        assertFalse(InputValidator.isNumeric(null));
    }

    @Test
    void testIsValidLength() {
        assertTrue(InputValidator.isValidLength("hello", 3, 10));
        assertTrue(InputValidator.isValidLength("hi", 2, 5));
        assertTrue(InputValidator.isValidLength("", 0, 5));
        
        assertFalse(InputValidator.isValidLength("hello", 1, 3));
        assertFalse(InputValidator.isValidLength("hello", 6, 10));
        
        // Null handling
        assertTrue(InputValidator.isValidLength(null, 0, 5));
        assertFalse(InputValidator.isValidLength(null, 1, 5));
    }

    @Test
    void testContainsDangerousChars() {
        assertTrue(InputValidator.containsDangerousChars("<script>alert('xss')</script>"));
        assertTrue(InputValidator.containsDangerousChars("javascript:alert('xss')"));
        assertTrue(InputValidator.containsDangerousChars("onload=alert('xss')"));
        assertTrue(InputValidator.containsDangerousChars("Some text with ' quotes"));
        assertTrue(InputValidator.containsDangerousChars("SQL injection; DROP TABLE"));
        
        assertFalse(InputValidator.containsDangerousChars("normal text"));
        assertFalse(InputValidator.containsDangerousChars("user@example.com"));
        assertFalse(InputValidator.containsDangerousChars(""));
        assertFalse(InputValidator.containsDangerousChars(null));
    }

    @Test
    void testSanitizeInput() {
        assertEquals("", InputValidator.sanitizeInput("<script>alert('xss')</script>"));
        assertEquals("alert(xss)", InputValidator.sanitizeInput("javascript:alert('xss')"));
        assertEquals("alert(xss)", InputValidator.sanitizeInput("onload=alert('xss')"));
        assertEquals("Hello World", InputValidator.sanitizeInput("Hello World"));
        assertEquals("normal text", InputValidator.sanitizeInput("normal text"));
        
        assertNull(InputValidator.sanitizeInput(null));
    }

    @Test
    void testIsValidUsername() {
        assertTrue(InputValidator.isValidUsername("user123"));
        assertTrue(InputValidator.isValidUsername("testuser"));
        assertTrue(InputValidator.isValidUsername("abc"));
        assertTrue(InputValidator.isValidUsername("USER123"));
        
        assertFalse(InputValidator.isValidUsername("ab")); // too short
        assertFalse(InputValidator.isValidUsername("a".repeat(31))); // too long
        assertFalse(InputValidator.isValidUsername("user-123")); // contains dash
        assertFalse(InputValidator.isValidUsername("user@123")); // contains @
        assertFalse(InputValidator.isValidUsername(""));
        assertFalse(InputValidator.isValidUsername(null));
    }

    @Test
    void testIsValidPassword() {
        assertTrue(InputValidator.isValidPassword("password123"));
        assertTrue(InputValidator.isValidPassword("mySecurePass1"));
        assertTrue(InputValidator.isValidPassword("abcdefg1"));
        
        assertFalse(InputValidator.isValidPassword("short1")); // too short
        assertFalse(InputValidator.isValidPassword("password")); // no numbers
        assertFalse(InputValidator.isValidPassword("12345678")); // no letters
        assertFalse(InputValidator.isValidPassword(""));
        assertFalse(InputValidator.isValidPassword(null));
    }
}