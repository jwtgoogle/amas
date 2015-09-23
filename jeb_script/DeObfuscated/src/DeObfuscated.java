import jeb.api.IScript;
import jeb.api.JebInstance;
import jeb.api.dex.Dex;
import jeb.api.dex.DexClass;
import jeb.api.dex.DexField;
import jeb.api.ui.View;

import java.util.List;
import java.util.Random;

/**
 * from : https://github.com/CunningLogic/myJEBPlugins
 * DeObfuscated:
 * Plugin that renames classes/fields/methods from non-latin names to easier to read names
 * <p/>
 * Modify By Lai
 */
public class DeObfuscated implements IScript {
    int showErrors = 0; // Show errors, slows the plugin down greatly.
    int renameShort = 1; // Rename short names, such as a, Ab, AbC
    int renameAll = 1; // Renames all classes, regardless if the match the isValid rules
    int renameNonLatin = 1; // Rename classes using non-latin chars
    int smartRename = 1; // Rename classes based on their type /not implemented/

    /**
     * @param length String length
     * @return random string
     */
    public static String generateRandomStr(int length) {
        String base = "abcdefghijklmnopqrstuvwxyz";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public void run(JebInstance jeb) {
        Dex dex = jeb.getDex();

        String classPre = "Class_";
        String innerPre = "InnerClass_";
        String fieldPre = "F_";
        String methodPre = "M_";

        if (showErrors == 0) {
            jeb.print("Show Errors is disabled");
        } else {
            jeb.print("Show Errors is enabled, this slows the script down!");
        }

        int count = 0;

        if (!jeb.isFileLoaded()) {
            jeb.print("Please load a DEX/APK file.");
        } else {
            jeb.print("Renaming fields...");
            List<String> arr = jeb.getDex().getFieldSignatures(true);
            for (int i = arr.size() - 1; i >= 0; i--) {
                String fieldName = arr.get(i);

                String type = "";
                DexField dexField = dex.getField(i);
                String fieldType = dex.getType(dexField.getTypeIndex());
                if (!fieldType.contains("$")) {
                    if (fieldType.startsWith("[")) {
                        type = fieldType.replace("[", "arr_");
                    } else if (fieldType.contains("/")) {
                        String tmp = fieldType.substring(fieldType.lastIndexOf('/') + 1, fieldType.length() - 1);
                        if (tmp.matches("\\w+")) {
                            type = tmp;
                        }
                    } else {
                        type = fieldType;
                    }
                }

                if (!isValid(fieldName.substring(fieldName.indexOf(">") + 1, fieldName.indexOf(":")))) {
                    ++count;

                    try {
                        if (!jeb.setFieldComment(fieldName, "Renamed from " + fieldName)) {
                            if (showErrors != 0)
                                jeb.print("Error commenting field " + fieldName);
                        }
                        if (!jeb.renameField(fieldName, type + fieldPre + Integer.toString(count))) {
                            if (showErrors != 0)
                                jeb.print("Error renaming field " + fieldName);
                        }

                    } catch (NullPointerException e) {
                        if (showErrors != 0)
                            jeb.print(e.toString() + " when renaming" + fieldName);

                    } catch (RuntimeException e) {
                        if (showErrors != 0)
                            jeb.print(e.toString() + " when renaming" + fieldName);

                    }
                }

            }

            arr.clear();
            jeb.print("Renaming methods...");
            arr = jeb.getDex().getMethodSignatures(true);
            for (int i = arr.size() - 1; i >= 0; i--) {
                String methodSig = arr.get(i);

                if (!isValid(methodSig.substring(methodSig.indexOf(">") + 1, methodSig.indexOf("(")))) {
                    try {
                        if (!jeb.setMethodComment(methodSig, "Renamed from " + methodSig)) {
                            if (showErrors != 0)
                                jeb.print("Error commenting method " + methodSig);
                        }
                        if (!jeb.renameMethod(methodSig, methodPre + generateRandomStr(2))) {
                            if (showErrors != 0)
                                jeb.print("Error renaming method " + methodSig);
                        }

                    } catch (NullPointerException e) {
                        if (showErrors != 0)
                            jeb.print(e.toString() + " when renaming" + methodSig);

                    } catch (RuntimeException e) {
                        if (showErrors != 0)
                            jeb.print(e.toString() + " when renaming" + methodSig);

                    }


                }

            }

            count = 0;
            arr.clear();
            jeb.print("Renaming classes...");
            arr = jeb.getDex().getClassSignatures(true);

            for (int i = arr.size() - 1; i >= 0; i--) {
                String classSig = arr.get(i);

                DexClass dexClass = dex.getClass(i);
                String superClassSig = dex.getType(dexClass.getSuperclassIndex());
                String superClassName = "";
                if (!arr.contains(superClassSig) && !superClassSig.contains(classPre) && !superClassSig.contains("Ljava/lang/Object;")) {
                    superClassName = superClassSig.substring(superClassSig.lastIndexOf('/') + 1, superClassSig.length() - 1) + "_";
                }

                String className = classSig.substring(classSig.lastIndexOf("/") + 1, classSig.length() - 1);

                if (!isValid(className)) {
                    ++count;

                    try {

                        if (!jeb.setClassComment(classSig, "Renamed from " + classSig)) {
                            if (showErrors != 0)
                                jeb.print("Error commenting class " + classSig);
                        }

                        if (classSig.contains("$")) {
                            if (!jeb.renameClass(classSig, superClassName + innerPre + Integer.toString(count))) {
                                if (showErrors != 0)
                                    jeb.print("Error renaming class " + classSig);
                            }
                        } else {
                            if (!jeb.renameClass(classSig, superClassName + classPre + Integer.toString(count))) {
                                if (showErrors != 0)
                                    jeb.print("Error renaming class " + classSig);
                            }
                        }

                    } catch (NullPointerException e) {
                        if (showErrors != 0)
                            jeb.print(e.toString() + " when renaming" + classSig);

                    } catch (RuntimeException e) {
                        if (showErrors != 0)
                            jeb.print(e.toString() + " when renaming" + classSig);

                    }
                }

            }

            jeb.getUI().getView(View.Type.CLASS_HIERARCHY).refresh();
            jeb.getUI().getView(View.Type.ASSEMBLY).refresh();
            jeb.print("Finished Renaming");
        }

    }

    public boolean isValid(String name) {
        // Handle inner classes
        if (name.contains("$")) {
            name = name.replace("$", "");
            if (name.length() <= 1) {
                return false;
            }
        }

        // Trying to do away with null pointers in method comments, not working.
        if (name.length() == 0 || name.contains("<init>") || name.contains("<clinit>"))
            return true;

        // Rename all classes
        if (renameAll != 0)
            return false;

        // Rename short class names, like output from ProGuard/Allatori
        if (renameShort != 0 && name.length() <= 2)
            return false;

        // Rename classes using non-latin chars
        if (renameNonLatin != 0 && !name.matches("\\w+"))
            return false;

        return true;
    }

}
