package com.github.dcimarc.himaya.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PathTraversalProtectionTest {

    @Test
    void testIsPathSafe_WithSafePath() {
        assertTrue(PathTraversalProtection.isPathSafe("documents/file.txt"));
        assertTrue(PathTraversalProtection.isPathSafe("images/photo.jpg"));
        assertTrue(PathTraversalProtection.isPathSafe("file.txt"));
    }

    @Test
    void testIsPathSafe_WithDangerousPath() {
        assertFalse(PathTraversalProtection.isPathSafe("../../../etc/passwd"));
        assertFalse(PathTraversalProtection.isPathSafe("..\\..\\windows\\system32"));
        assertFalse(PathTraversalProtection.isPathSafe("/etc/passwd"));
        assertFalse(PathTraversalProtection.isPathSafe("C:\\Windows\\System32"));
    }

    @Test
    void testIsPathWithinDirectory(@TempDir Path tempDir) throws IOException {
        File baseDir = tempDir.toFile();
        String basePath = baseDir.getAbsolutePath();
        
        // Create a test file within the directory
        File testFile = new File(baseDir, "test.txt");
        testFile.createNewFile();
        
        assertTrue(PathTraversalProtection.isPathWithinDirectory(basePath, "test.txt"));
        assertTrue(PathTraversalProtection.isPathWithinDirectory(basePath, "subfolder/test.txt"));
    }

    @Test
    void testSanitizePath() {
        // normalize() preserves leading .. that cannot be resolved
        assertEquals("../file.txt", PathTraversalProtection.sanitizePath("../file.txt"));
        assertEquals("documents/file.txt", PathTraversalProtection.sanitizePath("documents/../documents/file.txt"));
        assertEquals("path/to/file.txt", PathTraversalProtection.sanitizePath("path//to///file.txt"));
        assertEquals("path/to/file.txt", PathTraversalProtection.sanitizePath("path\\\\to\\\\file.txt"));
        assertEquals("path/to/file.txt", PathTraversalProtection.sanitizePath("/path/to/file.txt"));
    }

    @Test
    void testCreateSafePath(@TempDir Path tempDir) {
        String baseDirectory = tempDir.toString();
        
        String safePath = PathTraversalProtection.createSafePath(baseDirectory, "documents/file.txt");
        assertNotNull(safePath);
        assertTrue(safePath.contains("documents"));
        assertTrue(safePath.contains("file.txt"));
        
        // Test with dangerous path
        assertThrows(IllegalArgumentException.class, () -> {
            PathTraversalProtection.createSafePath(baseDirectory, "../../../etc/passwd");
        });
    }
}