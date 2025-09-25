# Java Himaya (حماية)

A Java security library implementing various security utilities for educational purposes. Himaya means "protection" in Arabic.

## Features

This library provides security utilities to help protect against common vulnerabilities:

- **Path Traversal Protection**: Prevent directory traversal attacks
- **Input Validation**: Validate and sanitize user input to prevent XSS, injection attacks, etc.

## Installation

Add this library to your Maven project:

```xml
<dependency>
    <groupId>com.github.dci-marc</groupId>
    <artifactId>java-himaya</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Usage

### Quick Start

The main entry point is the `HimayaSecurity` class, which provides convenient access to all utilities:

```java
import com.github.dcimarc.himaya.security.HimayaSecurity;

// Path traversal protection
if (HimayaSecurity.paths().isPathSafe("documents/file.txt")) {
    // Process safe path
}

// Input validation
if (HimayaSecurity.input().isValidEmail("user@example.com")) {
    // Process valid email
}
```

### Path Traversal Protection

Protect against directory traversal attacks:

```java
import com.github.dcimarc.himaya.security.PathTraversalProtection;

// Check if a path is safe (doesn't contain traversal sequences)
boolean safe = PathTraversalProtection.isPathSafe("documents/file.txt"); // true
boolean unsafe = PathTraversalProtection.isPathSafe("../../../etc/passwd"); // false

// Validate path is within a base directory
boolean withinDir = PathTraversalProtection.isPathWithinDirectory("/app/uploads", "user/photo.jpg");

// Sanitize a path (normalize and clean up)
String clean = PathTraversalProtection.sanitizePath("documents//file.txt"); // "documents/file.txt"

// Create a safe path combination
String safePath = PathTraversalProtection.createSafePath("/app/uploads", "user/photo.jpg");
```

### Input Validation

Validate and sanitize user input:

```java
import com.github.dcimarc.himaya.security.InputValidator;

// Email validation
boolean validEmail = InputValidator.isValidEmail("user@example.com"); // true

// Character type validation
boolean alphanumeric = InputValidator.isAlphanumeric("user123"); // true
boolean alphabetic = InputValidator.isAlphabetic("username"); // true
boolean numeric = InputValidator.isNumeric("12345"); // true

// Length validation
boolean validLength = InputValidator.isValidLength("password", 8, 50); // true

// Check for dangerous characters (XSS, injection attempts)
boolean dangerous = InputValidator.containsDangerousChars("<script>alert('xss')</script>"); // true

// Sanitize input
String clean = InputValidator.sanitizeInput("<script>alert('xss')</script>"); // ""

// Username and password validation
boolean validUser = InputValidator.isValidUsername("user123"); // true
boolean validPass = InputValidator.isValidPassword("mySecurePass1"); // true
```

## Security Features

### Path Traversal Protection

- **Path Safety Check**: Detects `../` sequences and absolute paths
- **Directory Boundary Validation**: Ensures paths stay within allowed directories
- **Path Normalization**: Uses Java's `Path.normalize()` for proper path resolution
- **Safe Path Creation**: Combines base directories with relative paths safely

### Input Validation

- **Email Format Validation**: RFC-compliant email pattern matching
- **Character Type Validation**: Alphanumeric, alphabetic, and numeric checks
- **Length Validation**: Configurable minimum and maximum length constraints
- **Dangerous Character Detection**: Identifies potential XSS and injection patterns
- **Input Sanitization**: Removes or escapes dangerous characters
- **Common Validation Patterns**: Username and password validation with security requirements

## Building from Source

```bash
git clone https://github.com/dci-marc/java-himaya.git
cd java-himaya
mvn clean compile
```

## Running Tests

```bash
mvn test
```

## Requirements

- Java 11 or higher
- Maven 3.6 or higher

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Educational Purpose

This library is created for educational purposes to demonstrate security concepts and best practices. While functional, it should not be used in production systems without thorough security review and testing.

## Contributing

This is an educational project. Feel free to fork and experiment, but please note that this is primarily for learning purposes.