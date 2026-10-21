package alienkrishn.qrylz;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableField;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * DEX side of the patch: loads the payload, swaps the signature placeholder for the
 * real certificate, merges the payload into the application dex and hooks the
 * application class.
 * <p>
 * The whole implementation rebuilds the dex from {@code Immutable*} model objects instead
 * of going through {@code RewriterModule}. The rewriter machinery only knows about type,
 * method and field references - it neither touches string references nor replaces the
 * method list of a class, so a placeholder that lives in a {@code const-string}
 * instruction or in a static field initialiser would survive it.
 */
public final class DexInjector {

    /** Placeholder in the payload that carries the original signature. */
    public static final String PLACEHOLDER = "PLACEHOLDER_SIG";

    /** Payload entry point that is called from the patched application class. */
    public static final String PAYLOAD_CLASS = "alienkrishn.qrylz.payload.QrylzPayload";

    private static final String CONTEXT_TYPE = "Landroid/content/Context;";

    private DexInjector() {
    }

    /**
     * Loads {@code payload.dex} and replaces the placeholder with the given signature.
     *
     * @param payloadBytes      raw payload dex
     * @param signatureBase64   Base64 of the DER encoded original certificate
     * @return the patched payload dex
     * @throws IOException when the payload cannot be parsed
     */
    public static DexFile loadPatchedPayload(byte[] payloadBytes, String signatureBase64)
            throws IOException {
        DexBackedDexFile payload = DexBackedDexFile.fromInputStream(
                Opcodes.getDefault(), new ByteArrayInputStream(payloadBytes));
        return replacePlaceholder(payload, PLACEHOLDER, signatureBase64);
    }

    /**
     * Replaces every occurrence of {@code placeholder} with {@code value}.
     * <p>
     * Both places a string can hide are handled: the {@code const-string} instruction
     * (dex format 21c) and the initial value of a static field.
     *
     * @param dex         dex to rewrite
     * @param placeholder text to look for
     * @param value       replacement
     * @return the rewritten dex
     */
    public static DexFile replacePlaceholder(DexFile dex, String placeholder, String value) {
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef classDef : dex.getClasses()) {
            List<Field> fields = new ArrayList<>();
            for (Field field : classDef.getFields()) {
                fields.add(replaceInField(field, placeholder, value));
            }
            List<Method> methods = new ArrayList<>();
            for (Method method : classDef.getMethods()) {
                methods.add(replaceInMethod(method, placeholder, value));
            }
            classes.add(new ImmutableClassDef(
                    classDef.getType(),
                    classDef.getAccessFlags(),
                    classDef.getSuperclass(),
                    classDef.getInterfaces(),
                    classDef.getSourceFile(),
                    classDef.getAnnotations(),
                    fields,
                    methods));
        }
        return new ImmutableDexFile(dex.getOpcodes(), classes);
    }

    /**
     * Merges the payload classes into the application dex.
     *
     * @param target  the application dex
     * @param payload the payload dex
     * @return a dex containing both
     * @throws IllegalStateException when both dex files define the same class
     */
    public static DexFile merge(DexFile target, DexFile payload) {
        List<ClassDef> classes = new ArrayList<>();
        Set<String> types = new HashSet<>();
        for (ClassDef classDef : target.getClasses()) {
            classes.add(classDef);
            types.add(classDef.getType());
        }
        for (ClassDef classDef : payload.getClasses()) {
            if (!types.add(classDef.getType())) {
                throw new IllegalStateException(
                        "Payload class " + classDef.getType() + " already exists in the target dex");
            }
            classes.add(classDef);
        }
        return new ImmutableDexFile(target.getOpcodes(), classes);
    }

    /**
     * Hooks the application class so that the payload is started before anything else
     * in the process runs.
     * <p>
     * The call is prepended to {@code attachBaseContext(Context)}. When the class does not
     * have that method yet, an overriding one is created that installs the payload and
     * then forwards to the super class.
     *
     * @param dex              dex to rewrite
     * @param applicationClass fully qualified name of the application class
     * @param payloadClass     fully qualified name of the payload entry point
     * @return the rewritten dex
     * @throws IllegalArgumentException when the application class is not in this dex
     */
    public static DexFile injectApplicationHook(DexFile dex, String applicationClass,
                                                String payloadClass) {
        String applicationType = toType(applicationClass);
        ClassDef target = null;
        for (ClassDef classDef : dex.getClasses()) {
            if (classDef.getType().equals(applicationType)) {
                target = classDef;
                break;
            }
        }
        if (target == null) {
            throw new IllegalArgumentException(
                    "Application class " + applicationClass + " not found in this dex");
        }

        List<Method> methods = new ArrayList<>();
        boolean patched = false;
        for (Method method : target.getMethods()) {
            if (!patched && isAttachBaseContext(method)) {
                methods.add(hookExisting(method, payloadClass));
                patched = true;
            } else {
                methods.add(method);
            }
        }
        if (!patched) {
            methods.add(createAttachBaseContext(target, payloadClass));
        }

        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef classDef : dex.getClasses()) {
            // Compare by name: a backed dex hands out fresh class objects on every
            // getClasses() call, so identity comparison would never match.
            if (classDef.getType().equals(applicationType)) {
                classes.add(new ImmutableClassDef(
                        classDef.getType(),
                        classDef.getAccessFlags(),
                        classDef.getSuperclass(),
                        classDef.getInterfaces(),
                        classDef.getSourceFile(),
                        classDef.getAnnotations(),
                        classDef.getFields(),
                        methods));
            } else {
                classes.add(classDef);
            }
        }
        return new ImmutableDexFile(dex.getOpcodes(), classes);
    }

    /**
     * @return {@code true} when the application class already overrides
     *         {@code attachBaseContext(Context)}
     */
    public static boolean hasAttachBaseContext(DexFile dex, String applicationClass) {
        String applicationType = toType(applicationClass);
        for (ClassDef classDef : dex.getClasses()) {
            if (!classDef.getType().equals(applicationType)) {
                continue;
            }
            for (Method method : classDef.getMethods()) {
                if (isAttachBaseContext(method)) {
                    return true;
                }
            }
        }
        return false;
    }
    public static boolean containsClass(DexFile dex, String className) {
        String type = toType(className);
        for (ClassDef classDef : dex.getClasses()) {
            if (classDef.getType().equals(type)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Writes a dex to disk.
     *
     * @param dex   dex to write
     * @param target destination file
     * @throws IOException when the file cannot be written
     */
    public static void writeDexFile(DexFile dex, File target) throws IOException {
        DexFileFactory.writeDexFile(target.getAbsolutePath(), dex);
    }

    // ------------------------------------------------------------------ helpers

    private static Field replaceInField(Field field, String placeholder, String value) {
        EncodedValue initial = field.getInitialValue();
        if (initial instanceof StringEncodedValue
                && placeholder.equals(((StringEncodedValue) initial).getValue())) {
            return new ImmutableField(
                    field.getDefiningClass(),
                    field.getName(),
                    field.getType(),
                    field.getAccessFlags(),
                    new ImmutableStringEncodedValue(value),
                    field.getAnnotations(),
                    field.getHiddenApiRestrictions());
        }
        return field;
    }

    private static Method replaceInMethod(Method method, String placeholder, String value) {
        MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            return method;
        }
        List<Instruction> instructions = new ArrayList<>();
        boolean changed = false;
        for (Instruction instruction : implementation.getInstructions()) {
            if (instruction instanceof Instruction21c) {
                Reference reference = ((Instruction21c) instruction).getReference();
                if (reference instanceof StringReference
                        && placeholder.equals(((StringReference) reference).getString())) {
                    instructions.add(new BuilderInstruction21c(
                            Opcode.CONST_STRING,
                            ((Instruction21c) instruction).getRegisterA(),
                            new ImmutableStringReference(value)));
                    changed = true;
                    continue;
                }
            }
            instructions.add(instruction);
        }
        if (!changed) {
            return method;
        }
        return new ImmutableMethod(
                method.getDefiningClass(),
                method.getName(),
                method.getParameters(),
                method.getReturnType(),
                method.getAccessFlags(),
                method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                new ImmutableMethodImplementation(
                        implementation.getRegisterCount(),
                        instructions,
                        ImmutableTryBlock.immutableListOf(implementation.getTryBlocks()),
                        implementation.getDebugItems()));
    }

    private static boolean isAttachBaseContext(Method method) {
        List<? extends CharSequence> parameters = method.getParameterTypes();
        return "attachBaseContext".equals(method.getName())
                && parameters.size() == 1
                // The parameter list holds CharSequence elements, not plain strings once
                // the method went through the immutable model.
                && CONTEXT_TYPE.contentEquals(parameters.get(0));
    }

    /**
     * Prepends the payload call to an existing {@code attachBaseContext}.
     * <p>
     * The register count is left untouched: the incoming parameters always live in the
     * highest registers, so changing the count would shift them and invalidate every
     * register reference of the original body.
     */
    private static Method hookExisting(Method method, String payloadClass) {
        MethodImplementation implementation = method.getImplementation();
        List<Instruction> instructions = new ArrayList<>();
        instructions.add(installCall(payloadClass, contextRegister(implementation)));
        for (Instruction instruction : implementation.getInstructions()) {
            instructions.add(instruction);
        }
        return new ImmutableMethod(
                method.getDefiningClass(),
                method.getName(),
                method.getParameters(),
                method.getReturnType(),
                method.getAccessFlags(),
                method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                new ImmutableMethodImplementation(
                        implementation.getRegisterCount(),
                        instructions,
                        ImmutableTryBlock.immutableListOf(implementation.getTryBlocks()),
                        implementation.getDebugItems()));
    }

    /**
     * Creates an {@code attachBaseContext} that installs the payload and then forwards to
     * the super class.
     */
    private static Method createAttachBaseContext(ClassDef target, String payloadClass) {
        // this + the context parameter, no locals needed: the payload call only needs the
        // context register.
        int registerCount = 2;
        int contextRegister = registerCount - 1;
        int thisRegister = registerCount - 2;

        List<Instruction> instructions = new ArrayList<>();
        instructions.add(installCall(payloadClass, contextRegister));
        instructions.add(new BuilderInstruction35c(
                Opcode.INVOKE_SUPER,
                2,
                thisRegister,
                contextRegister,
                0,
                0,
                0,
                new ImmutableMethodReference(
                        target.getSuperclass(),
                        "attachBaseContext",
                        Collections.singletonList(CONTEXT_TYPE),
                        "V")));
        instructions.add(new BuilderInstruction10x(Opcode.RETURN_VOID));

        return new ImmutableMethod(
                target.getType(),
                "attachBaseContext",
                Collections.singletonList(new ImmutableMethodParameter(CONTEXT_TYPE, null, null)),
                "V",
                AccessFlags.PUBLIC.getValue(),
                null,
                null,
                new ImmutableMethodImplementation(registerCount, instructions, null, null));
    }

    private static Instruction installCall(String payloadClass, int contextRegister) {
        return new BuilderInstruction35c(
                Opcode.INVOKE_STATIC,
                1,
                contextRegister,
                0,
                0,
                0,
                0,
                new ImmutableMethodReference(
                        toType(payloadClass),
                        "install",
                        Collections.singletonList(CONTEXT_TYPE),
                        "V"));
    }

    /**
     * @return the register that holds the context parameter of an instance method
     */
    private static int contextRegister(MethodImplementation implementation) {
        // Parameters occupy the highest registers, the context is the last one.
        return implementation.getRegisterCount() - 1;
    }

    private static String toType(String className) {
        return "L" + className.replace('.', '/') + ";";
    }
}
