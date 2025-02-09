/*
 * Copyright 2021 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@file:Suppress("ResultOfMethodCallIgnored")

package org.openrewrite.java.security

import org.junit.jupiter.api.Test
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class UseFilesCreateTempDirectoryTest : RewriteTest {
    override fun defaults(spec: RecipeSpec) {
        spec.recipe(UseFilesCreateTempDirectory())
    }

    @Test
    fun useFilesCreateTempDirectory() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.IOException;
            
            class A {
                void b() throws IOException {
                    File tempDir;
                    tempDir = File.createTempFile("OverridesTest", "dir");
                    tempDir.delete();
                    tempDir.mkdir();
                    System.out.println(tempDir.getAbsolutePath());
                }
            }
        """,
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;
            
            class A {
                void b() throws IOException {
                    File tempDir;
                    tempDir = Files.createTempDirectory("OverridesTest" + "dir").toFile();
                    System.out.println(tempDir.getAbsolutePath());
                }
            }
        """
        )
    )

    @Test
    fun useFilesCreateTempDirectoryWithParentDir() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class A {
                File testData = Files.createTempDirectory("").toFile();
                void b() throws IOException {
                    File tmpDir = File.createTempFile("test", "dir", testData);
                    tmpDir.delete();
                    tmpDir.mkdir();
                }
            }
        """,
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class A {
                File testData = Files.createTempDirectory("").toFile();
                void b() throws IOException {
                    File tmpDir = Files.createTempDirectory(testData.toPath(), "test" + "dir").toFile();
                }
            }
        """
        )
    )

    @Test
    fun useFilesCreateTempDirectory2() = rewriteRun(
        java(
            """
                import java.io.File;
                import java.io.IOException;
    
                class A {
                    void b() throws IOException {
                        File tempDir = File.createTempFile("abc", "def");
                        tempDir.delete();
                        tempDir.mkdir();
                        System.out.println(tempDir.getAbsolutePath());
                        tempDir = File.createTempFile("efg", "hij");
                        tempDir.delete();
                        tempDir.mkdir();
                        System.out.println(tempDir.getAbsolutePath());
                    }
                }
            """.trimIndent(),
            """
                import java.io.File;
                import java.io.IOException;
                import java.nio.file.Files;
    
                class A {
                    void b() throws IOException {
                        File tempDir = Files.createTempDirectory("abc" + "def").toFile();
                        System.out.println(tempDir.getAbsolutePath());
                        tempDir = Files.createTempDirectory("efg" + "hij").toFile();
                        System.out.println(tempDir.getAbsolutePath());
                    }
                }
            """.trimIndent()
        )
    )

    @Test
    fun onlySupportAssignmentToJIdentifier() = rewriteRun(
        java(
            """
                package abc;
                import java.io.File;
                public class C {
                    public static File FILE;
                }
            """
        ),
        java(
            """
                package abc;
                import java.io.File;
                import java.io.IOException;
    
                class A {
                    void b() throws IOException {
                        C.FILE = File.createTempFile("cfile", "txt");
                        File tempDir = File.createTempFile("abc", "png");
                        tempDir.delete();
                        tempDir.mkdir();
                    }
                }
            """.trimIndent(),
            """
                package abc;
                import java.io.File;
                import java.io.IOException;
                import java.nio.file.Files;
    
                class A {
                    void b() throws IOException {
                        C.FILE = File.createTempFile("cfile", "txt");
                        File tempDir = Files.createTempDirectory("abc" + "png").toFile();
                    }
                }
            """.trimIndent()
        )
    )

    @Suppress("RedundantThrows")
    @Test
    fun `Vulnerable File#mkdir() with tmpdir path param`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.IOException;

            class T {
                void vulnerableFileCreateTempFileMkdirTainted() throws IOException {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    tempDirChild.mkdir();
                }
            }
        """
        )
    )

    @Test
    fun `Vulnerable File#mkdir() with tmpdir path param does not throw Exception`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.IOException;

            class T {
                void vulnerableFileCreateTempFileMkdirTainted() {
                    File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                    tempDirChild.mkdir();
                }
            }
        """
        )
    )

    @Test
    fun `Uses mkdirs recipe assumes is that the directory exists otherwise the existing code would also fail`() =
        rewriteRun(
            java(
                """
                    import java.io.File;
                    import java.io.IOException;
        
                    class T {
                        public void doSomething() throws IOException {
                            File tmpDir = new File("/some/dumb/thing");
                            tmpDir.mkdirs();
                            if (!tmpDir.isDirectory()) {
                                System.out.println("Mkdirs failed to create " + tmpDir);
                            }
                            final File workDir = File.createTempFile("unjar", "", tmpDir);
                            workDir.delete();
                            workDir.mkdirs();
                            if (!workDir.isDirectory()) {
                                System.out.println("Mkdirs failed to create " + workDir);
                            }
                        }
                    }
                """.trimIndent(),
                """
                    import java.io.File;
                    import java.io.IOException;
                    import java.nio.file.Files;
        
                    class T {
                        public void doSomething() throws IOException {
                            File tmpDir = new File("/some/dumb/thing");
                            tmpDir.mkdirs();
                            if (!tmpDir.isDirectory()) {
                                System.out.println("Mkdirs failed to create " + tmpDir);
                            }
                            final File workDir = Files.createTempDirectory(tmpDir.toPath(), "unjar" + "").toFile();
                            if (!workDir.isDirectory()) {
                                System.out.println("Mkdirs failed to create " + workDir);
                            }
                        }
                    }
                """.trimIndent()
            )
        )

    @Test
    fun `delete wrapped in an if block`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class A {
                File testData = Files.createTempDirectory("").toFile();
                void b() throws IOException {
                    File tmpDir = File.createTempFile("test", "dir", testData);
                    if (!tmpDir.delete()) {
                        System.out.println("Failed to delete directory!");
                    }
                    tmpDir.mkdir();
                }
            }
        """,
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class A {
                File testData = Files.createTempDirectory("").toFile();
                void b() throws IOException {
                    File tmpDir = Files.createTempDirectory(testData.toPath(), "test" + "dir").toFile();
                }
            }
        """
        )
    )

    @Test
    fun `delete & mkdirs wrapped in an if block`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class A {
                File testData = Files.createTempDirectory("").toFile();
                void b() throws IOException {
                    File tmpDir = File.createTempFile("test", "dir", testData);
                    if (!tmpDir.delete() || !tmpDir.mkdir()) {
                        throw new IOException("Failed to or create directory!");
                    }
                }
            }
        """,
            """
            import java.io.File;
            import java.io.IOException;
            import java.nio.file.Files;

            class A {
                File testData = Files.createTempDirectory("").toFile();
                void b() throws IOException {
                    File tmpDir = Files.createTempDirectory(testData.toPath(), "test" + "dir").toFile();
                }
            }
        """
        )
    )

    @Suppress("ConstantConditions")
    @Test
    fun `boolean operator on race calls`() = rewriteRun(
        java(
            """
                import java.io.File;
                import java.io.IOException;
    
                class A {
                    File b() throws IOException {
                        boolean success = true;
                        File temp = File.createTempFile("test", "directory");
                        success &= temp.delete();
                        success &= temp.mkdir();
                        if (success) {
                            return temp;
                        } else {
                            throw new RuntimeException("Failed to create directory");
                        }
                    }
                }
            """.trimIndent(),
            """
                import java.io.File;
                import java.io.IOException;
                import java.nio.file.Files;
    
                class A {
                    File b() throws IOException {
                        boolean success = true;
                        File temp = Files.createTempDirectory("test" + "directory").toFile();
                        if (success) {
                            return temp;
                        } else {
                            throw new RuntimeException("Failed to create directory");
                        }
                    }
                }
            """.trimIndent()
        )
    )

    @Test
    fun `multiple calls to delete`() = rewriteRun(
        java(
            """
                import java.io.File;
                import java.io.FileWriter;
                import java.io.IOException;
                
                class A {
                    void b() throws IOException {
                        boolean success = true;
                        File temp = File.createTempFile("test", "directory");
                        temp.delete();
                        temp.mkdir();
                        File textFile = new File(temp, "test.txt");
                        try (FileWriter writer = new FileWriter(textFile)) {
                            writer.write("Hello World!");
                        } finally {
                            textFile.delete();
                            temp.delete();
                        }
                    }
                }
            """,
            """
                import java.io.File;
                import java.io.FileWriter;
                import java.io.IOException;
                import java.nio.file.Files;
                
                class A {
                    void b() throws IOException {
                        boolean success = true;
                        File temp = Files.createTempDirectory("test" + "directory").toFile();
                        File textFile = new File(temp, "test.txt");
                        try (FileWriter writer = new FileWriter(textFile)) {
                            writer.write("Hello World!");
                        } finally {
                            textFile.delete();
                            temp.delete();
                        }
                    }
                }
            """
        )
    )

    @Test
    fun `strange chain that calls through new File`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileWriter;
            import java.io.IOException;

            class A {
                void createWorkingDir() throws IOException {
                    File temp = File.createTempFile("temp", Long.toString(System.nanoTime()));
                    temp.delete();
                    temp = new File(temp.getAbsolutePath() + ".d");
                    temp.mkdir();
                }
            }
        """
        )
    )
}
