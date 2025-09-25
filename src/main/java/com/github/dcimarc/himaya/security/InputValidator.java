package com.github.dcimarc.himaya.security;

import java.util.regex.Pattern;

/**
 * Utility class for input validation and sanitization.
 * Provides methods to validate and sanitize various types of user input
 * to prevent security vulnerabilities like XSS, SQL injection, etc.
 */
public class InputValidator {

    // Common regex patterns for validation
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );
    
    private static final Pattern ALPHANUMERIC_PATTERN = Pattern.compile("^[a-zA-Z0-9]+$");
    private static final Pattern ALPHA_PATTERN = Pattern.compile("^[a-zA-Z]+$");
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^[0-9]+$");
    
    // Dangerous characters that might indicate malicious input
    private static final String[] DANGEROUS_CHARS = {
        "<script", "</script>", "javascript:", "onload=", "onerror=",
        "onclick=", "onmouseover=", "'", "\"", ";", "--", "/*", "*/"
    };

    /**
     * Validates an email address format.
     *
     * @param email the email address to validate
     * @return true if the email is valid, false otherwise
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    /**
     * Validates that a string contains only alphanumeric characters.
     *
     * @param input the string to validate
     * @return true if the string is alphanumeric, false otherwise
     */
    public static boolean isAlphanumeric(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return ALPHANUMERIC_PATTERN.matcher(input).matches();
    }

    /**
     * Validates that a string contains only alphabetic characters.
     *
     * @param input the string to validate
     * @return true if the string contains only letters, false otherwise
     */
    public static boolean isAlphabetic(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return ALPHA_PATTERN.matcher(input).matches();
    }

    /**
     * Validates that a string contains only numeric characters.
     *
     * @param input the string to validate
     * @return true if the string is numeric, false otherwise
     */
    public static boolean isNumeric(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return NUMERIC_PATTERN.matcher(input).matches();
    }

    /**
     * Validates that a string length is within the specified range.
     *
     * @param input the string to validate
     * @param minLength minimum allowed length
     * @param maxLength maximum allowed length
     * @return true if the length is valid, false otherwise
     */
    public static boolean isValidLength(String input, int minLength, int maxLength) {
        if (input == null) {
            return minLength <= 0;
        }
        int length = input.length();
        return length >= minLength && length <= maxLength;
    }

    /**
     * Checks if the input contains potentially dangerous characters
     * that might indicate XSS or injection attempts.
     *
     * @param input the string to check
     * @return true if dangerous characters are found, false otherwise
     */
    public static boolean containsDangerousChars(String input) {
        if (input == null) {
            return false;
        }
        
        String lowerInput = input.toLowerCase();
        for (String dangerousChar : DANGEROUS_CHARS) {
            if (lowerInput.contains(dangerousChar)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sanitizes input by removing or escaping dangerous characters.
     * This is a basic implementation for educational purposes.
     *
     * @param input the string to sanitize
     * @return sanitized string
     */
    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        
        return input
                .replaceAll("<script[^>]*>.*?</script>", "") // Remove script tags
                .replaceAll("javascript:", "")               // Remove javascript: protocol
                .replaceAll("on\\w+\\s*=", "")              // Remove event handlers
                .replaceAll("[<>\"'&]", "")                 // Remove dangerous HTML chars
                .trim();
    }

    /**
     * Validates a username according to common security practices.
     * Username should be alphanumeric, 3-30 characters long.
     *
     * @param username the username to validate
     * @return true if the username is valid, false otherwise
     */
    public static boolean isValidUsername(String username) {
        return username != null && 
               isValidLength(username, 3, 30) && 
               isAlphanumeric(username) &&
               !containsDangerousChars(username);
    }

    /**
     * Validates a password strength.
     * Password should be at least 8 characters long and contain
     * at least one letter and one number.
     *
     * @param password the password to validate
     * @return true if the password meets minimum requirements, false otherwise
     */
    public static boolean isValidPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }
        
        boolean hasLetter = password.matches(".*[a-zA-Z].*");
        boolean hasDigit = password.matches(".*[0-9].*");
        
        return hasLetter && hasDigit;
    }
}