package org.openrewrite.java.security

import org.junit.jupiter.api.Test
import org.openrewrite.java.JavaRecipeTest

class PreventTempFileInformationDisclosure : JavaRecipeTest {

    @Test
    fun safeFileCreateTempFilesCreateFile() = assertUnchanged(
        before = """
            import java.io.IOException;
            import java.io.File;
            import java.nio.file.Files;
            import java.nio.file.attribute.PosixFilePermission;
            import java.nio.file.attribute.PosixFilePermissions;
            import java.util.EnumSet;
            
            class T {
                void safeFileCreateTempFilesCreateFile() throws IOException {
                    // Clear permissions intentions by setting the 'OWNER_READ' and 'OWNER_WRITE'
                    // permissions.
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child-create-file.txt");
                    Files.createFile(tempDirChild.toPath(), PosixFilePermissions.asFileAttribute(
                        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
                    );
                }
            }
        """
    )
}