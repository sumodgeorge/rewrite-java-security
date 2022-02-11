package org.openrewrite.java.security.tempfile;

import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.TypeUtils;

import java.util.function.Supplier;

public class SecureTempFileJavaTemplateHelper {

    public static final String HELPER_CLASS_NAME = "SecureTempFileHelper";
    public static final String CREATE_TEMP_DIR_FOR_PATH = "createTempDir";

    private static final String[] IMPOORTS = new String[]{
            "java.io.File",
            "java.io.IOException",
            "java.io.UncheckedIOException",
            "java.nio.file.Files",
            "java.nio.file.Path",
            "java.nio.file.attribute.FileAttribute",
            "java.nio.file.attribute.PosixFilePermission",
            "java.nio.file.attribute.PosixFilePermissions",
            "java.util.EnumSet"};

    private static String buildClass(String... methods) {
        return "private static class " +
                HELPER_CLASS_NAME +
                " {\n" +
                String.join("\n", methods) +
                "}";
    }

    public static class FileMkdirToTempFileHelperMkDir extends JavaIsoVisitor<ExecutionContext> {
        private final MethodMatcher fileMkdirMatcher = new MethodMatcher("java.io.File mkdir()");
        private final J.Identifier select;

        public FileMkdirToTempFileHelperMkDir(J.Identifier select) {
            this.select = select;
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, executionContext);
            if (fileMkdirMatcher.matches(mi) && select.equals(mi.getSelect())) {
                mi = mi.withTemplate(createTempDirForPathTemplate(this::getCursor, select), mi.getCoordinates().replace(), select);
            }
            return mi;
        }

        private JavaTemplate createTempDirForPathTemplate(Supplier<Cursor> cursorSupplier, J.Identifier select) {
            StringBuilder template = new StringBuilder(HELPER_CLASS_NAME);
            template.append(".").append(CREATE_TEMP_DIR_FOR_PATH);
            if (TypeUtils.isOfClassType(select.getType(), "java.io.File")) {
                template.append("(#{any(java.io.File)}.toPath());");
            } else if (TypeUtils.isOfClassType(select.getType(), "java.nio.files.Path")) {
                template.append("(#{any(java.nio.Path)});");
            }
            return JavaTemplate.builder(cursorSupplier, template.toString()).imports(IMPOORTS).build();
        }

    }

    public static class AddSecureTempFileClassVisitor extends JavaIsoVisitor<ExecutionContext> {
        private final JavaTemplate template;

        public AddSecureTempFileClassVisitor(String... helperMethods) {
            template = JavaTemplate.builder(this::getCursor, buildClass(helperMethods))
                    .imports(IMPOORTS)
                    .build();
        }

        @Override
        public J.ClassDeclaration visitClassDeclaration(J.ClassDeclaration classDecl, ExecutionContext executionContext) {
            J.ClassDeclaration cd = super.visitClassDeclaration(classDecl, executionContext);
            //noinspection ConstantConditions
            if (getCursor().getParent().getValue() instanceof J.CompilationUnit) {
                cd = cd.withTemplate(template, cd.getBody().getCoordinates().lastStatement());
                for (String impoort : IMPOORTS) {
                    maybeAddImport(impoort);
                }
            }
            return cd;
        }

    }
    
    public static String CREATE_TEMP_DIR_FOR_PATH_METHOD =
            "    static void " + CREATE_TEMP_DIR_FOR_PATH + "(Path tempDirChild) {\n" +
            "        try {\n" +
            "            if (tempDirChild.getFileSystem().supportedFileAttributeViews().contains(\"posix\")) {\n" +
            "                // Explicit permissions setting is only required on unix-like systems because\n" +
            "                // the temporary directory is shared between all users.\n" +
            "                // This is not necessary on Windows, each user has their own temp directory\n" +
            "                final EnumSet<PosixFilePermission> posixFilePermissions =\n" +
            "                        EnumSet.of(\n" +
            "                            PosixFilePermission.OWNER_READ, \n" +
            "                            PosixFilePermission.OWNER_WRITE,\n" +
            "                            PosixFilePermission.OWNER_EXECUTE\n" +
            "                        );\n" +
            "                if (!Files.exists(tempDirChild)) {\n" +
            "                    Files.createDirectory(\n" +
            "                            tempDirChild,\n" +
            "                            PosixFilePermissions.asFileAttribute(posixFilePermissions)\n" +
            "                    );\n" +
            "                } else {\n" +
            "                    Files.setPosixFilePermissions(\n" +
            "                            tempDirChild,\n" +
            "                            posixFilePermissions\n" +
            "                    );\n" +
            "                }\n" +
            "            } else if (!Files.exists(tempDirChild)) {\n" +
            "                // On Windows, we still need to create the directory, when it doesn't already exist.\n" +
            "                Files.createDirectory(tempDirChild);\n" +
            "            }\n" +
            "        } catch (IOException exception) {\n" +
            "            throw new UncheckedIOException(\"Failed to create temp file\", exception);\n" +
            "        }\n" +
            "    }";
}
