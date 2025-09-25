package com.github.dcimarc.himaya.security;

/**
 * Main utility class for the Himaya Security library.
 * Provides convenient access to various security utilities.
 * 
 * Himaya (حماية) means "protection" in Arabic.
 */
public class HimayaSecurity {
    
    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private HimayaSecurity() {
        throw new AssertionError("Utility class should not be instantiated");
    }
    
    /**
     * Gets the version of the Himaya Security library.
     *
     * @return the library version
     */
    public static String getVersion() {
        return "1.0.0-SNAPSHOT";
    }
    
    /**
     * Provides quick access to path traversal protection utilities.
     * 
     * Example usage:
     * <pre>
     * if (HimayaSecurity.paths().isPathSafe("user/documents/file.txt")) {
     *     // Process the file
     * }
     * </pre>
     *
     * @return PathTraversalProtection utility methods
     */
    public static PathTraversalProtectionHelper paths() {
        return PathTraversalProtectionHelper.INSTANCE;
    }
    
    /**
     * Provides quick access to input validation utilities.
     * 
     * Example usage:
     * <pre>
     * if (HimayaSecurity.input().isValidEmail("user@example.com")) {
     *     // Process the email
     * }
     * </pre>
     *
     * @return InputValidator utility methods
     */
    public static InputValidatorHelper input() {
        return InputValidatorHelper.INSTANCE;
    }
    
    /**
     * Helper class for path traversal protection methods.
     */
    public static class PathTraversalProtectionHelper {
        private static final PathTraversalProtectionHelper INSTANCE = new PathTraversalProtectionHelper();
        
        private PathTraversalProtectionHelper() {}
        
        public boolean isPathSafe(String filePath) {
            return PathTraversalProtection.isPathSafe(filePath);
        }
        
        public boolean isPathWithinDirectory(String basePath, String filePath) {
            return PathTraversalProtection.isPathWithinDirectory(basePath, filePath);
        }
        
        public String sanitizePath(String filePath) {
            return PathTraversalProtection.sanitizePath(filePath);
        }
        
        public String createSafePath(String baseDirectory, String relativePath) {
            return PathTraversalProtection.createSafePath(baseDirectory, relativePath);
        }
    }
    
    /**
     * Helper class for input validation methods.
     */
    public static class InputValidatorHelper {
        private static final InputValidatorHelper INSTANCE = new InputValidatorHelper();
        
        private InputValidatorHelper() {}
        
        public boolean isValidEmail(String email) {
            return InputValidator.isValidEmail(email);
        }
        
        public boolean isAlphanumeric(String input) {
            return InputValidator.isAlphanumeric(input);
        }
        
        public boolean isAlphabetic(String input) {
            return InputValidator.isAlphabetic(input);
        }
        
        public boolean isNumeric(String input) {
            return InputValidator.isNumeric(input);
        }
        
        public boolean isValidLength(String input, int minLength, int maxLength) {
            return InputValidator.isValidLength(input, minLength, maxLength);
        }
        
        public boolean containsDangerousChars(String input) {
            return InputValidator.containsDangerousChars(input);
        }
        
        public String sanitizeInput(String input) {
            return InputValidator.sanitizeInput(input);
        }
        
        public boolean isValidUsername(String username) {
            return InputValidator.isValidUsername(username);
        }
        
        public boolean isValidPassword(String password) {
            return InputValidator.isValidPassword(password);
        }
    }
}