package com.github.dcimarc.himaya;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import static org.junit.jupiter.api.Assertions.*;

class HimayaTest {

  @Test
  void testGetVersion() {
    String version = Himaya.getVersion();
    assertNotNull(version);
    assertEquals("0.1.5", version);
  }

  @Test
  void testUtilityClassCannotBeInstantiated() {
    // Use reflection to access the private constructor
    final Constructor<Himaya>[] constructor = new Constructor[1];
    assertThrows(AssertionError.class, () -> constructor[0] = Himaya.class.getDeclaredConstructor());

    constructor[0].setAccessible(true);
    Exception exception = assertThrows(Exception.class, constructor[0]::newInstance);

    // The AssertionError should be wrapped in an InvocationTargetException
    assertInstanceOf(InvocationTargetException.class, exception);
    assertInstanceOf(AssertionError.class, exception.getCause());
  }

  @Test
  void testPathHelperFunctionality() {
    // Test that the helper provides access to path traversal protection
    assertTrue(Himaya.paths().isPathSafe("documents/file.txt"));
    assertFalse(Himaya.paths().isPathSafe("../../../etc/passwd"));

    String sanitized = Himaya.paths().sanitizePath("../documents/file.txt");
    assertEquals("../documents/file.txt", sanitized); // normalize() preserves leading ..
  }

  @Test
  void testInputHelperFunctionality() {
    // Test that the helper provides access to input validation
    assertTrue(Himaya.input().isValidEmail("user@example.com"));
    assertFalse(Himaya.input().isValidEmail("invalid-email"));

    assertTrue(Himaya.input().isAlphanumeric("abc123"));
    assertFalse(Himaya.input().isAlphanumeric("abc-123"));

    assertTrue(Himaya.input().containsDangerousChars("<script>"));
    assertFalse(Himaya.input().containsDangerousChars("normal text"));

    String sanitized = Himaya.input().sanitizeInput("<script>alert('xss')</script>");
    assertEquals("", sanitized);
  }

  @Test
  void testHelpersSingleton() {
    // Test that helpers are singletons
    assertSame(Himaya.paths(), Himaya.paths());
    assertSame(Himaya.input(), Himaya.input());
  }
}