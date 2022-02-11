package org.openrewrite.java.security.tempfile;

import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;

public class PreventTempDirectoryHijackingVisitor extends JavaIsoVisitor<ExecutionContext> {

    private static final MethodMatcher SYSTEM_PROPERTY_MATCHER = new MethodMatcher("System getProperty(String)");
    private static final MethodMatcher NEW_FILE_MATCHER = new MethodMatcher("java.io.File <constructor>(..)");
    private static final MethodMatcher FILE_MKDIR_MATCHER = new MethodMatcher("java.io.File mkdir()");

    @Override
    public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
        J.MethodInvocation mi = super.visitMethodInvocation(method, executionContext);
        if (SYSTEM_PROPERTY_MATCHER.matches(mi) && mi.getArguments().get(0) instanceof J.Literal
                && "java.io.tmpdir".equals(((J.Literal) mi.getArguments().get(0)).getValue())) {
            getEnclosingCursor().putMessage("TMP_DIR_PROP", mi);
        } else if (FILE_MKDIR_MATCHER.matches(mi)) {
            //noinspection ConstantConditions
            getEnclosingCursor().putMessage("FILE_MKDIR", mi.getSelect());
        }
        return mi;
    }

    @Override
    public J.NewClass visitNewClass(J.NewClass newClass, ExecutionContext executionContext) {
        J.NewClass nc = super.visitNewClass(newClass, executionContext);
        if (NEW_FILE_MATCHER.matches(nc)) {
            getEnclosingCursor().putMessage("NEW_FILE", nc);
        }
        return nc;
    }

    @Override
    public J.VariableDeclarations.NamedVariable visitVariable(J.VariableDeclarations.NamedVariable variable, ExecutionContext executionContext) {
        J.VariableDeclarations.NamedVariable nv = super.visitVariable(variable, executionContext);
        if (getCursor().pollMessage("NEW_FILE") != null && getCursor().pollMessage("TMP_DIR_PROP") != null) {
            getEnclosingCursor().putMessage("TMP_FILE_VAR", nv);
        }
        return nv;
    }

    @Override
    public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
        J.Block bl = super.visitBlock(block, executionContext);
        Expression mkdirSelect = getCursor().pollMessage("FILE_MKDIR");
        J.VariableDeclarations.NamedVariable tmpDirVar = getCursor().pollMessage("TMP_FILE_VAR");
        if (tmpDirVar == null) {
            tmpDirVar = getCursor().dropParentUntil(J.ClassDeclaration.class::isInstance).getMessage("TMP_FILE_VAR");
        }
        if (tmpDirVar != null && mkdirSelect instanceof J.Identifier) {
            doAfterVisit(new SecureTempFileJavaTemplateHelper.AddSecureTempFileClassVisitor(SecureTempFileJavaTemplateHelper.CREATE_TEMP_DIR_FOR_PATH_METHOD));
            doAfterVisit(new SecureTempFileJavaTemplateHelper.FileMkdirToTempFileHelperMkDir((J.Identifier)mkdirSelect));
        }
        return bl;
    }

    private Cursor getEnclosingCursor() {
        return getCursor().dropParentUntil(v -> v instanceof J.Block
                || v instanceof J.VariableDeclarations.NamedVariable
                || v instanceof J.MethodInvocation
                || v instanceof J.MethodDeclaration
                ||v instanceof J.ClassDeclaration);
    }
}
