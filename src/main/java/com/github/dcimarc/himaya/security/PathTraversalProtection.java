package com.github.dcimarc.himaya.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

/**
 * Utility class for preventing path traversal attacks.
 * Provides methods to validate and sanitize file paths to prevent
 * unauthorized access to files outside of allowed directories.
 */
public class PathTraversalProtection {

    /**
     * Validates that a given file path is safe and does not contain
     * path traversal sequences like "../" or "..\".
     *
     * @param filePath the file path to validate
     * @return true if the path is safe, false otherwise
     * @throws IllegalArgumentException if filePath is null
     */
    public static boolean isPathSafe(String filePath) {
        if (filePath == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }

        // Normalize the path to resolve any ".." or "." components
        String normalizedPath = Paths.get(filePath).normalize().toString();
        
        // Check for path traversal patterns
        return !normalizedPath.contains("..") && 
               !normalizedPath.startsWith("/") && 
               !normalizedPath.matches("^[A-Za-z]:[/\\\\].*");
    }

    /**
     * Validates that a file path is within the specified base directory.
     *
     * @param basePath the base directory path
     * @param filePath the file path to validate
     * @return true if the file path is within the base directory, false otherwise
     * @throws IllegalArgumentException if any parameter is null
     */
    public static boolean isPathWithinDirectory(String basePath, String filePath) {
        Objects.requireNonNull(basePath, "Base path cannot be null");
        Objects.requireNonNull(filePath, "File path cannot be null");

        try {
            Path base = Paths.get(basePath).toRealPath();
            Path file = Paths.get(basePath, filePath).normalize();
            
            return file.startsWith(base);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Sanitizes a file path by normalizing it and ensuring it's a relative path.
     * This method uses Path.normalize() which resolves "." and ".." components
     * where possible, but preserves leading ".." components that cannot be resolved.
     *
     * @param filePath the file path to sanitize
     * @return sanitized file path
     * @throws IllegalArgumentException if filePath is null
     */
    public static String sanitizePath(String filePath) {
        if (filePath == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }

        // First, normalize the path to resolve directory traversal sequences
        Path normalized = Paths.get(filePath).normalize();
        String result = normalized.toString();
        
        // Convert backslashes to forward slashes for consistency
        result = result.replaceAll("\\\\+", "/");
        
        // Replace multiple slashes with single slash
        result = result.replaceAll("//+", "/");
        
        // Remove leading slash if present to ensure relative path
        if (result.startsWith("/")) {
            result = result.substring(1);
        }
        
        return result.trim();
    }

    /**
     * Creates a safe file path by combining a base directory with a relative path.
     * This method ensures the resulting path stays within the base directory.
     *
     * @param baseDirectory the base directory
     * @param relativePath the relative path to combine
     * @return a safe file path or null if the combination would escape the base directory
     * @throws IllegalArgumentException if any parameter is null
     */
    public static String createSafePath(String baseDirectory, String relativePath) {
        Objects.requireNonNull(baseDirectory, "Base directory cannot be null");
        Objects.requireNonNull(relativePath, "Relative path cannot be null");

        // First normalize the relative path to see what it resolves to
        Path normalizedRelative = Paths.get(relativePath).normalize();
        String normalizedStr = normalizedRelative.toString();
        
        // If the normalized path contains ".." or starts with "/", it's trying to escape
        if (normalizedStr.contains("..") || normalizedStr.startsWith("/") || 
            normalizedStr.matches("^[A-Za-z]:[/\\\\].*")) {
            return null;
        }

        Path basePath = Paths.get(baseDirectory).normalize();
        Path combinedPath = basePath.resolve(normalizedRelative).normalize();

        // Ensure the combined path is still within the base directory
        if (!combinedPath.startsWith(basePath)) {
            return null;
        }

        return combinedPath.toString();
    }
}