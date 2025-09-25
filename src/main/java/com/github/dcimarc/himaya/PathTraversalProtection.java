package com.github.dcimarc.himaya;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Utility class for preventing path traversal attacks.
 * Provides methods to validate and sanitize file paths to prevent
 * unauthorized access to files outside of allowed directories.
 */
public class PathTraversalProtection {

  private PathTraversalProtection() {
    throw new AssertionError("Utility class should not be instantiated");
  }

  /**
   * Validates that a given file path is safe and does not contain
   * path traversal sequences like "../" or "..\".
   *
   * @param filePath the file path to validate
   * @return true if the path is safe, false otherwise
   * @throws IllegalArgumentException if filePath is null
   */
  public static boolean isPathSafe(@NotNull String filePath) {
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
  public static boolean isPathWithinDirectory(@NotNull String basePath, @NotNull String filePath) {
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
  public static @NotNull String sanitizePath(@NotNull String filePath) {
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
   * @param relativePath  the relative path to combine
   * @return a safe file path or null if the combination would escape the base directory
   * @throws IllegalArgumentException if any parameter is null or if the relative path attempts to escape the base directory
   */
  public static @NotNull String createSafePath(@NotNull String baseDirectory, @NotNull String relativePath) {
    // First normalize the relative path to see what it resolves to
    Path normalizedRelative = Paths.get(relativePath).normalize();
    String normalizedStr = normalizedRelative.toString();

    // If the normalized path contains ".." or starts with "/", it's trying to escape
    if (normalizedStr.contains("..") || normalizedStr.startsWith("/") ||
        normalizedStr.matches("^[A-Za-z]:[/\\\\].*")) {
      throw new IllegalArgumentException("Relative path attempts to escape base directory");
    }

    Path basePath = Paths.get(baseDirectory).normalize();
    Path combinedPath = basePath.resolve(normalizedRelative).normalize();

    // Ensure the combined path is still within the base directory
    if (!combinedPath.startsWith(basePath)) {
      throw new IllegalArgumentException("Resulting path escapes the base directory");
    }

    return combinedPath.toString();
  }
}