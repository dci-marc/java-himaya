package com.github.dcimarc.himaya;

import org.jetbrains.annotations.NotNull;

/**
 * Main utility class for the Himaya Security library.
 * Provides convenient access to various security utilities.
 * <p>
 * Himaya (حماية) means "protection" in Arabic.
 */
public class Himaya {

  private static final @NotNull String VERSION = "0.1.4";

  /**
   * Private constructor to prevent instantiation of utility class.
   */
  private Himaya() {
    throw new AssertionError("Utility class should not be instantiated");
  }

  /**
   * Gets the version of the Himaya Security library.
   *
   * @return the library version
   */
  public static @NotNull String getVersion() {
    return Himaya.VERSION;
  }

  /**
   * Provides quick access to path traversal protection utilities.
   * <p>
   * Example usage:
   * <pre>
   * if (HimayaSecurity.paths().isPathSafe("user/documents/file.txt")) {
   *     // Process the file
   * }
   * </pre>
   *
   * @return PathTraversalProtection utility methods
   */
  public static @NotNull PathTraversalProtectionHelper paths() {
    return PathTraversalProtectionHelper.INSTANCE;
  }

  /**
   * Provides quick access to input validation utilities.
   * <p>
   * Example usage:
   * <pre>
   * if (HimayaSecurity.input().isValidEmail("user@example.com")) {
   *     // Process the email
   * }
   * </pre>
   *
   * @return InputValidator utility methods
   */
  public static @NotNull InputValidatorHelper input() {
    return InputValidatorHelper.INSTANCE;
  }

  /**
   * Helper class for path traversal protection methods.
   */
  public static class PathTraversalProtectionHelper {
    private static final @NotNull PathTraversalProtectionHelper INSTANCE = new PathTraversalProtectionHelper();

    private PathTraversalProtectionHelper() {
    }

    public boolean isPathSafe(@NotNull String filePath) {
      return PathTraversalProtection.isPathSafe(filePath);
    }

    public boolean isPathWithinDirectory(@NotNull String basePath, @NotNull String filePath) {
      return PathTraversalProtection.isPathWithinDirectory(basePath, filePath);
    }

    public @NotNull String sanitizePath(@NotNull String filePath) {
      return PathTraversalProtection.sanitizePath(filePath);
    }

    public @NotNull String createSafePath(@NotNull String baseDirectory, @NotNull String relativePath) {
      return PathTraversalProtection.createSafePath(baseDirectory, relativePath);
    }
  }

  /**
   * Helper class for input validation methods.
   */
  public static class InputValidatorHelper {
    private static final @NotNull InputValidatorHelper INSTANCE = new InputValidatorHelper();

    private InputValidatorHelper() {
    }

    public boolean isValidEmail(@NotNull String email) {
      return InputValidator.isValidEmail(email);
    }

    public boolean isAlphanumeric(@NotNull String input) {
      return InputValidator.isAlphanumeric(input);
    }

    public boolean isAlphabetic(@NotNull String input) {
      return InputValidator.isAlphabetic(input);
    }

    public boolean isNumeric(@NotNull String input) {
      return InputValidator.isNumeric(input);
    }

    public boolean isValidLength(@NotNull String input, int minLength, int maxLength) {
      return InputValidator.isValidLength(input, minLength, maxLength);
    }

    public boolean containsDangerousChars(@NotNull String input) {
      return InputValidator.containsDangerousChars(input);
    }

    public @NotNull String sanitizeInput(@NotNull String input) {
      return InputValidator.sanitizeInput(input);
    }

    public boolean isValidUsername(@NotNull String username) {
      return InputValidator.isValidUsername(username);
    }

    public boolean isValidPassword(@NotNull String password) {
      return InputValidator.isValidPassword(password);
    }
  }
}