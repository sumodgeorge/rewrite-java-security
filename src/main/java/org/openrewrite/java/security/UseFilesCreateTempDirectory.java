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
package org.openrewrite.java.security;

import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.marker.JavaVersion;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.*;

import java.time.Duration;
import java.util.*;

public class UseFilesCreateTempDirectory extends Recipe {

    private static final MethodMatcher CREATE_TEMP_FILE_MATCHER = new MethodMatcher("java.io.File createTempFile(..)");

    @Override
    public String getDisplayName() {
        return "Use Files#createTempDirectory";
    }

    @Override
    public String getDescription() {
        return "Use `Files#createTempDirectory` when the sequence `File#createTempFile(..)`->`File#delete()`->`File#mkdir()` is used for creating a temp directory.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("RSPEC-5445");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(10);
    }

    @Override
    protected JavaVisitor<ExecutionContext> getSingleSourceApplicableTest() {
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
                doAfterVisit(new UsesMethod<>("java.io.File createTempFile(..)"));
                doAfterVisit(new UsesMethod<>("java.io.File mkdir(..)"));
                return super.visitJavaSourceFile(cu, executionContext);
            }
        };
    }

    @Override
    protected UsesFilesCreateTempDirVisitor getVisitor() {
        return new UsesFilesCreateTempDirVisitor();
    }

    private static class UsesFilesCreateTempDirVisitor extends JavaIsoVisitor<ExecutionContext> {
        private static final MethodMatcher DELETE_MATCHER = new MethodMatcher("java.io.File delete()");
        private static final MethodMatcher MKDIR_MATCHER = new MethodMatcher("java.io.File mkdir()");
        private static final MethodMatcher SYSTEM_PROPERTY_MATCHER = new MethodMatcher("System getProperty(java.lang.String)");

        @Override
        public JavaSourceFile visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
            Optional<JavaVersion> javaVersion = cu.getMarkers().findFirst(JavaVersion.class);
            if (javaVersion.isPresent() && javaVersion.get().getMajorVersion() < 7) {
                return cu;
            }
            return super.visitJavaSourceFile(cu, executionContext);
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, executionContext);
            J.VariableDeclarations.NamedVariable tempFileVar = getCursor().getNearestMessage("TEMP_DIR_FILE_VAR");
            if (CREATE_TEMP_FILE_MATCHER.matches(mi)) {
                J.Block block = getCursor().firstEnclosing(J.Block.class);
                if (block != null) {
                    J createFileStatement = null;
                    J firstParent = getCursor().dropParentUntil(J.class::isInstance).getValue();
                    if (firstParent instanceof J.Assignment && ((J.Assignment)firstParent).getVariable() instanceof J.Identifier) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement == null && firstParent instanceof J.VariableDeclarations.NamedVariable) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement != null) {
                        getCursor().dropParentUntil(J.Block.class::isInstance)
                                .computeMessageIfAbsent("CREATE_FILE_STATEMENT", v -> new ArrayList<J>()).add(createFileStatement);
                    }
                }
            } else if (tempFileVar != null && isMethodForIdent(tempFileVar.getName(), MKDIR_MATCHER, mi) && parentBlockThrowsIOExceptionOrException()) {
                mi = mi.withTemplate(JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(java.io.File)}.toPath(), UUID.randomUUID().toString()).toFile();")
                        .imports("java.nio.file.Files", "java.util.UUID").build(), mi.getCoordinates().replace(), tempFileVar.getName());
                maybeAddImport("java.nio.file.Files");
                maybeAddImport("java.util.UUID");
            }
            return mi;
        }

        @Override
        public J.VariableDeclarations.NamedVariable visitVariable(J.VariableDeclarations.NamedVariable variable, ExecutionContext executionContext) {
            J.VariableDeclarations.NamedVariable var = super.visitVariable(variable, executionContext);
            if (TypeUtils.isOfClassType(var.getType(),"java.io.File") && var.getInitializer() != null && var.getInitializer() instanceof J.NewClass) {
                J.NewClass newFileInitializer = (J.NewClass)var.getInitializer();
                if (newFileInitializer.getArguments() != null && !newFileInitializer.getArguments().isEmpty() && newFileInitializer.getArguments().get(0) instanceof J.MethodInvocation) {
                    J.MethodInvocation newFileParentArg = (J.MethodInvocation)newFileInitializer.getArguments().get(0);
                    if (SYSTEM_PROPERTY_MATCHER.matches(newFileParentArg) && newFileParentArg.getArguments().get(0) instanceof J.Literal) {
                        if ("java.io.tmpdir".equals(((J.Literal)newFileParentArg.getArguments().get(0)).getValue())) {
                            getCursor().dropParentUntil(J.Block.class::isInstance).putMessage("TEMP_DIR_FILE_VAR", var);
                        }
                    }
                }
            }
            return var;
        }

        @Override
        public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
            J.Block bl = super.visitBlock(block, executionContext);
            List<J> createFileStatements = getCursor().pollMessage("CREATE_FILE_STATEMENT");
            if (createFileStatements != null) {
                for (J createFileStatement : createFileStatements) {
                    List<Statement> statements = bl.getStatements();
                    int statementIndex = -1;
                    Statement createTempDirectoryStatement = null;
                    for (int i = 0; i < statements.size() - 2; i++) {
                        Statement stmt = statements.get(i);
                        J.Identifier createFileIdentifier = getIdent(createFileStatement);
                        if (createFileIdentifier != null && isMatchingCreateFileStatement(createFileStatement, stmt)
                                && isMethodForIdent(createFileIdentifier, DELETE_MATCHER, statements.get(i + 1))
                                && isMethodForIdent(createFileIdentifier, MKDIR_MATCHER, statements.get(i + 2))) {
                            createTempDirectoryStatement = (Statement) new SecureTempDirectoryCreation().visitNonNull(stmt, executionContext, getCursor());
                            statementIndex = i;
                            break;
                        }
                    }
                    if (createTempDirectoryStatement != null) {
                        List<Statement> updatedStatements = new ArrayList<>(statements);
                        updatedStatements.remove(statementIndex);
                        updatedStatements.remove(statementIndex);
                        updatedStatements.remove(statementIndex);
                        updatedStatements.add(statementIndex, createTempDirectoryStatement);
                        bl = bl.withStatements(updatedStatements);
                        maybeAddImport("java.nio.file.Files");
                    }
                }
            }
            return bl;
        }


        private boolean isMatchingCreateFileStatement(J createFileStatement, Statement statement) {
            if (createFileStatement.equals(statement)) {
                return true;
            }
            if (createFileStatement instanceof J.VariableDeclarations.NamedVariable && statement instanceof J.VariableDeclarations) {
                J.VariableDeclarations varDecls = (J.VariableDeclarations) statement;
                for (J.VariableDeclarations.NamedVariable variable : varDecls.getVariables()) {
                    if (variable.equals(createFileStatement)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private boolean isMethodForIdent(J.Identifier ident, MethodMatcher methodMatcher, Statement statement) {
            if (statement instanceof J.MethodInvocation) {
                J.MethodInvocation mi = (J.MethodInvocation) statement;
                if (mi.getSelect() instanceof J.Identifier && methodMatcher.matches(mi)) {
                    J.Identifier sel = (J.Identifier) mi.getSelect();
                    return ident.getSimpleName().equals(sel.getSimpleName())
                            && TypeUtils.isOfClassType(ident.getType(), "java.io.File");
                }
            }
            return false;
        }

        @Nullable
        private J.Identifier getIdent(J createFileStatement) {
            if (createFileStatement instanceof J.Assignment) {
                J.Assignment assignment = (J.Assignment) createFileStatement;
                return (J.Identifier) assignment.getVariable();
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable) {
                J.VariableDeclarations.NamedVariable var = (J.VariableDeclarations.NamedVariable) createFileStatement;
                return var.getName();
            }
            return null;
        }

        private boolean parentBlockThrowsIOExceptionOrException() {
            Cursor parent = getCursor().dropParentUntil(j -> j instanceof J.MethodDeclaration || j instanceof J.Try || j instanceof J.ClassDeclaration);
            J parentValue = parent.getValue();
            if (parentValue instanceof J.MethodDeclaration) {
                J.MethodDeclaration md = (J.MethodDeclaration) parentValue;
                return md.getThrows() != null && md.getThrows().stream().anyMatch(n -> isIOExceptionOrException(TypeUtils.asFullyQualified(n.getType())));
            } else if (parentValue instanceof J.Try) {
                J.Try tr = (J.Try) parentValue;
                return tr.getCatches().stream().anyMatch(n -> isIOExceptionOrException(TypeUtils.asFullyQualified(n.getParameter().getTree().getType())));
            }
            return false;
        }

        private boolean isIOExceptionOrException(@Nullable JavaType.FullyQualified fqCatch) {
            return fqCatch != null &&
                    ("java.io.IOException".matches(fqCatch.getFullyQualifiedName())
                            || "java.lang.Exception".matches(fqCatch.getFullyQualifiedName()));
        }
    }

    private static class SecureTempDirectoryCreation extends JavaIsoVisitor<ExecutionContext> {
        private final JavaTemplate twoArg = JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        private final JavaTemplate threeArg = JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(java.io.File)}.toPath(), #{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation m = method;
            if (CREATE_TEMP_FILE_MATCHER.matches(m)) {
                maybeAddImport("java.nio.file.Files");
                if (m.getArguments().size() == 2) {
                    // File.createTempFile(String prefix, String suffix)
                    m = m.withTemplate(twoArg,
                            m.getCoordinates().replace(),
                            m.getArguments().get(0),
                            m.getArguments().get(1)
                    );
                } else if (m.getArguments().size() == 3) {
                    // File.createTempFile(String prefix, String suffix, File dir)
                    m = m.withTemplate(threeArg,
                            m.getCoordinates().replace(),
                            m.getArguments().get(2),
                            m.getArguments().get(0),
                            m.getArguments().get(1)
                    );
                }
            }
            return m;
        }
    }
}
