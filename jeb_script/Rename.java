//? name=DeCluster v1.1.2, help=This Java file is a JEB plugin

import jeb.api.IScript;
import jeb.api.JebInstance;
import jeb.api.dex.Dex;
import jeb.api.dex.DexClass;
import jeb.api.ui.JebUI;
import jeb.api.ui.View;

import java.util.HashMap;

public class Rename implements IScript {
    private static Dex dex;
    private static JebInstance jeb;
    JebUI ui;

    public void run(JebInstance jebInstance) {
        jeb = jebInstance;
        dex = jeb.getDex();
        ui = jeb.getUI();

        jeb.print("Begin renaming classes ...");
        renameClasses();
        refreshViews();
        jeb.print("-- End --");
    }


    private void renameClasses() {
        int index;
        int classCount = dex.getClassCount();
        boolean result;
        for (index = 0; index < classCount; index++) {
            DexClass dexClass = dex.getClass(index);
            String className = dex.getType(dexClass.getClasstypeIndex());

            // TODO 如果非英文字符，则命名为aClass顺序
            // 
            result = renameBySuperClass(dexClass);
            if (!result) {
                result = renameByAccessor(dexClass);
                if (result) {
                    continue;
                }
                renameByInterfaces(dexClass);
            }

            if (result) {
                String newClassName = dex.getType(dexClass.getClasstypeIndex());
                jeb.print("rename from " + className + " to " + newClassName);
            }
        }
    }

    private boolean renameByInterfaces(DexClass dexClass) {
        int idx;
        int[] idxs = dexClass.getInterfaceIndexes();

        for (idx = 0; idx < idxs.length; idx++) {
            String ifName = dex.getType(idx);

            if (ifName.endsWith("ClickListener;")) {
                changeClassName(dexClass, "ClickListener");
                return true;
            } else if (ifName.endsWith("CancelListener;")) {
                changeClassName(dexClass, "CancelListener");
                return true;
            } else if (ifName.endsWith("Ljava/lang/Runnable;")) {
                changeClassName(dexClass, "Runnable");
                return true;
            } else if (ifName.endsWith("Landroid/os/IInterface;")) {
                changeClassName(dexClass, "IInterface");
                return true;
            }

            
                // put("java/io/Serializable;", "Serializable");
        }

        return false;
    }

    private boolean renameByAccessor(DexClass dexClass) {
        int flag = dexClass.getAccessFlags();

        if ((flag & 0x200) != 0) {
            changeClassName(dexClass, "Interface");
            return true;
        } else if ((flag & 0x400) != 0) {
            changeClassName(dexClass, "'Abstract'");
            return true;
        } else if ((flag & 0x4000) != 0) {
            changeClassName(dexClass, "Enum");
            return true;
        }

        return false;
    }

    private boolean renameBySuperClass(DexClass dexClass) {
        HashMap<String, String> superClassList = new HashMap<String, String>() {
            {
                put("Landroid/app/Activity;", "Activity");
                put("Landroid/content/BroadcastReceiver;", "Receiver");
                put("Landroid/app/Service;", "Service");
                put("Ljava/lang/Thread;", "Thread");
                put("Landroid/content/ContentProvider;", "Provider");
                put("Landroid/os/AsyncTask;", "AsyncTask");
                put("Ljava/util/TimerTask;", "TimerTask");
                put("Landroid/database/sqlite/SQLiteDatabase;", "SQLiteDatabase");
                put("Landroid/database/sqlite/SQLiteOpenHelper;", "SQLiteOpenHelper");
                put("Landroid/database/ContentObserver;", "ContentObserver");
                put("Landroid/os/Handler;", "Handler");
                put("Landroid/telephony/PhoneStateListener;", "PhoneStateListener");
                put("Landroid/app/admin/DeviceAdminReceiver;", "DeviceAdminReceiver");
            }
        };
        String superClassName = dex.getType(dexClass.getSuperclassIndex());
        if (superClassList.keySet().contains(superClassName)) {
            String value = superClassList.get(superClassName);
            changeClassName(dexClass, value);
            return true;
        }

        return false;
    }

    private void changeClassName(DexClass dexClass, String postfix) {
        String className = dex.getType(dexClass.getClasstypeIndex());

        if (className.contains(postfix)) {
            return;
        }

        int beginIndex = className.lastIndexOf('/') + 1;
        int endIndex = className.length() - 1;
        String newClassName = className.substring(beginIndex, endIndex) + "_" + postfix;

        jeb.renameClass(className, newClassName);
    }


    private void refreshViews() {
        ui.getView(View.Type.ASSEMBLY).refresh();
        ui.getView(View.Type.JAVA).refresh();
        ui.getView(View.Type.CLASS_HIERARCHY).refresh();
    }
}