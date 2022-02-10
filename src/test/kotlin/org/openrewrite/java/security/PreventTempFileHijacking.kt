package org.openrewrite.java.security

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.openrewrite.java.JavaRecipeTest

class PreventTempFileHijacking : JavaRecipeTest {

    @Test
    fun vulnerableFileCreateTempFilesWriteNotHijacking() = assertUnchanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.charset.StandardCharsets;
            import java.nio.file.Files;
            import java.nio.file.StandardOpenOption;
            import java.util.Collections;
            
            class T {
                void vulnerableFileCreateTempFilesWrite1() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.write(tempDirChild.toPath(), Collections.singletonList("secret"), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesWrite1() = assertChanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.charset.StandardCharsets;
            import java.nio.file.Files;
            import java.nio.file.StandardOpenOption;
            import java.util.Collections;
            
            class T {
                void vulnerableFileCreateTempFilesWrite1() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.write(tempDirChild.toPath(), Collections.singletonList("secret"), StandardCharsets.UTF_8, StandardOpenOption.CREATE);
                }
            }
        """,
        after = """
            import java.io.IOException;
            import java.io.File;
            import java.io.UncheckedIOException;
            import java.nio.charset.StandardCharsets;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.nio.file.attribute.PosixFilePermission;
            import java.util.Collections;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFilesWrite1() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    // TODO: FIX THIS BECAUSE IT WILL FAIL IF THE child.txt ALREADY EXISTS
                    Files.createFile(tempDirChild.toPath(), 
                            Collections.singletonList("secret"), 
                            StandardCharsets.UTF_8,
                            PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    Files.write(tempDirChild, Collections.singletonList("secret"));
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesWrite2() = assertChanged(
        before = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            
            class T {
                void vulnerableFileCreateTempFilesWrite2() throws IOException {
                    String secret = "secret";
                    byte[] byteArray = secret.getBytes();
                    
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.write(tempDirChild.toPath(), byteArray, StandardOpenOption.CREATE);
                }
            }
        """,
        after = """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFilesWrite2() throws IOException {
                    String secret = "secret";
                    byte[] byteArray = secret.getBytes();
                    
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child.txt");
                    Files.createFile(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    Files.write(tempDirChild, byteArray);
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesNewBufferedWriter() = assertChanged(
        before = """
            import java.io.BufferedWriter;
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            
            class T {
                void vulnerableFileCreateTempFilesNewBufferedWriter() throws IOException {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-buffered-writer.txt").toPath();
                    BufferedWriter bw = Files.newBufferedWriter(tempDirChild);
                }
            }
        """,
        after = """
            import java.io.BufferedWriter;
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            class T {
                void vulnerableFileCreateTempFilesNewBufferedWriter()  throws IOException  {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-buffered-writer.txt").toPath();
                    Files.createFile(tempDirChild, PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    BufferedWriter bw = Files.newBufferedWriter(tempDirChild);
                }
            }
        """
    )

    @Disabled
    @Test
    fun vulnerableFileCreateTempFilesNewOutputStream() = assertChanged(
        before = """
            import java.io.File;
            
            class T {
                void vulnerableFileCreateTempFilesNewOutputStream() {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-output-stream.txt").toPath();
                    Files.newOutputStream(tempDirChild).close();
                }
            }
        """,
        after = """
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void vulnerableFileCreateTempFilesNewOutputStream() {
                    Path tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-output-stream.txt").toPath();
                    Files.createFile(tempDirChild, PosixFilePermissions.asFileAttribute(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
                    Files.newOutputStream(tempDirChild).close();
                }
            }
        """
    )


}