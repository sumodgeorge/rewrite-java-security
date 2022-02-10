package org.openrewrite.java.security

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.openrewrite.java.JavaRecipeTest

class PreventTempDirectoryHijackingTest : JavaRecipeTest {

    @Suppress("ResultOfMethodCallIgnored", "RedundantThrows")
    @Test
    fun vulnerableFileCreateTempFileMkdirTainted() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;
            // does not check mkdir return and will continue even if dir already exists
            class T {
                void vulnerableFileCreateTempFileMkdirTainted() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    tempDirChild.mkdir();
                    // Assume that tempDirChild is used later
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.io.UncheckedIOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.FileAttribute;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFileMkdirTainted() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    PreventTempDirHijackingHelper.createTempDir(tempDirChild.toPath());
                }

                private static class PreventTempDirHijackingHelper {
                    static void createTempDir(Path tempDirChild) {
                        try {
                            if (tempDirChild.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                                // Explicit permissions setting is only required on unix-like systems because
                                // the temporary directory is shared between all users.
                                // This is not necessary on Windows, each user has their own temp directory
                                final EnumSet<PosixFilePermission> posixFilePermissions =
                                        EnumSet.of(
                                            PosixFilePermission.OWNER_READ, 
                                            PosixFilePermission.OWNER_WRITE,
                                            PosixFilePermission.OWNER_EXECUTE
                                        );
                                if (!Files.exists(tempDirChild)) {
                                    Files.createDirectory(
                                            tempDirChild,
                                            PosixFilePermissions.asFileAttribute(posixFilePermissions)
                                    );
                                } else {
                                    Files.setPosixFilePermissions(
                                            tempDirChild,
                                            posixFilePermissions
                                    );
                                }
                            } else if (!Files.exists(tempDirChild)) {
                                // On Windows, we still need to create the directory, when it doesn't already exist.
                                Files.createDirectory(tempDirChild);
                            }
                        } catch (IOException exception) {
                            throw new UncheckedIOException("Failed to create temp file", exception);
                        }
                    }
                }
            }
        """
    )

    @Suppress("ResultOfMethodCallIgnored")
    @Test
    fun vulnerableFileCreateTempFileMkdirsTainted() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFileMkdirsTainted() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child/grandchild");
                    tempDirChild.mkdirs();
                }
                
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.io.UncheckedIOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFileMkdirsTainted() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child/grandchild");
                    PreventTempDirHijackingHelper.createTempDirs(tempDirChild);
                }
                
                private static class PreventTempDirHijackingHelper {
                    static void createTempDirs(Path tempDirChild) {
                        try {
                            if (tempDirChild.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                                // Explicit permissions setting is only required on unix-like systems because
                                // the temporary directory is shared between all users.
                                // This is not necessary on Windows, each user has their own temp directory
                                final EnumSet<PosixFilePermission> posixFilePermissions =
                                        EnumSet.of(
                                            PosixFilePermission.OWNER_READ,
                                            PosixFilePermission.OWNER_WRITE,
                                            PosixFilePermission.OWNER_EXECUTE
                                        );
                                if (!Files.exists(tempDirChild)) {
                                    Files.createDirectory(
                                            tempDirChild,
                                            PosixFilePermissions.asFileAttribute(posixFilePermissions)
                                    );
                                } else {
                                    Files.setPosixFilePermissions(
                                            tempDirChild,
                                            posixFilePermissions
                                    );
                                }
                            } else if (!Files.exists(tempDirChild)) {
                                // On Windows, we still need to create the directory, when it doesn't already exist.
                                Files.createDirectory(tempDirChild);
                            }
                        } catch (IOException exception) {
                            throw new UncheckedIOException("Failed to create temp file", exception);
                        }
                    }
                }
            }
        """
    )


    @Disabled
    @Test
    fun vulnerableFileCreateDirectory() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateDirectory() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directory");
                    Files.createDirectory(tempDirChild.toPath());
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateDirectory() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directory");
                    PreventTempDirHijackingHelper.createTempDir(tempDirChild.toPath());
                }
                
                private static class PreventTempDirHijackingHelper {
                    static void createTempDir(Path tempDirChild) {
                        try {
                            if (tempDirChild.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                                // Explicit permissions setting is only required on unix-like systems because
                                // the temporary directory is shared between all users.
                                // This is not necessary on Windows, each user has their own temp directory
                                final EnumSet<PosixFilePermission> posixFilePermissions =
                                        EnumSet.of(
                                            PosixFilePermission.OWNER_READ, 
                                            PosixFilePermission.OWNER_WRITE,
                                            PosixFilePermission.OWNER_EXECUTE
                                        );
                                if (!Files.exists(tempDirChild)) {
                                    Files.createDirectory(
                                            tempDirChild,
                                            PosixFilePermissions.asFileAttribute(posixFilePermissions)
                                    );
                                } else {
                                    Files.setPosixFilePermissions(
                                            tempDirChild,
                                            posixFilePermissions
                                    );
                                }
                            } else if (!Files.exists(tempDirChild)) {
                                // On Windows, we still need to create the directory, when it doesn't already exist.
                                Files.createDirectory(tempDirChild);
                            }
                        } catch (IOException exception) {
                            throw new UncheckedIOException("Failed to create temp file", exception);
                        }
                    }
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateDirectories() = assertChanged(
        before = """
            import java.io.File;
            import java.nio.file.Files;
            import java.io.IOException;
            
            class T {
                void vulnerableFileCreateDirectories() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directories/child");
                    Files.createDirectories(tempDirChild.toPath());
                }
            }
        """,
        after = """
            import org.openrewrite.java.security.PreventTempFileHijacking;import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateDirectories() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-directories/child");
                    PreventTempDirHijackingHelper.createTempDirs(tempDirChild);
                }
                
                private static class PreventTempDirHijackingHelper {
                    static void createTempDirs(Path tempDirChild) {
                        try {
                            if (tempDirChild.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                                // Explicit permissions setting is only required on unix-like systems because
                                // the temporary directory is shared between all users.
                                // This is not necessary on Windows, each user has their own temp directory
                                final EnumSet<PosixFilePermission> posixFilePermissions =
                                        EnumSet.of(
                                            PosixFilePermission.OWNER_READ,
                                            PosixFilePermission.OWNER_WRITE,
                                            PosixFilePermission.OWNER_EXECUTE
                                        );
                                if (!Files.exists(tempDirChild)) {
                                    Files.createDirectory(
                                            tempDirChild,
                                            PosixFilePermissions.asFileAttribute(posixFilePermissions)
                                    );
                                } else {
                                    Files.setPosixFilePermissions(
                                            tempDirChild,
                                            posixFilePermissions
                                    );
                                }
                            } else if (!Files.exists(tempDirChild)) {
                                // On Windows, we still need to create the directory, when it doesn't already exist.
                                Files.createDirectory(tempDirChild);
                            }
                        } catch (IOException exception) {
                            throw new UncheckedIOException("Failed to create temp file", exception);
                        }
                    }
                }
            }
        """
    )


}