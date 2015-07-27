
import jeb
from jeb.api import IScript
from jeb.api.ast import Constant
import java.lang.System


class RiskApis(IScript):

    def run(self, jebInstance):
        self.jeb = jebInstance
        self.dex = self.jeb.getDex()
        self.classSignatures = self.dex.getClassSignatures(True)

        # 初始化
        # API保存在配置中
        # 加上一个交互按照类型检索 API
        # 1、SMS
        # 2、CMD
        # 3、广告Notify
        # 4、loaddex、loadso
        # 5、检查加壳
        # 6、设备管理器


        # 制定搜索的范围：根据选中的节点……遍历

        self.riskAPIs = {
            "abortBroadcast":"",
            "sendDataMessage":"",
            "sendTextMessage":"",
            "sendMultipartTextMessage":"",
            # "getDisplayMessageBody":"",
            # "getDisplayOriginatingAddress":"",
            # "getMessageBody":"",
            # "startRecording":"",
            # "requestWindowFeature":"",  # 界面置顶
            # "setComponentEnabledSetting":"",  # 隐藏图标
            # "Runtime.getRuntime":"",
            # "System.load":"",
            # "SQLiteDatabase ":"",

            # "getAssets().open":"",
            # "new DexClassLoader":"",
            # "new DexFile":"",
            # "new PathClassLoader":"",
            # "://":"",
            # "/system":"",
            # "Notification":""
            }

        
        
        for classSignature in self.classSignatures:
            try:
                javaCode = self.jeb.decompileClass(classSignature)
                if not javaCode :
                    continue
                for api in self.riskAPIs.keys():
                    flag = True
                    for line in javaCode.split("\n") :
                        if api in line:
                            if flag:
                                self.riskAPIs[api] = self.riskAPIs[api] + "\t- " + classSignature + "\n"
                                flag = False
                            self.riskAPIs[api] = self.riskAPIs[api] + "\t" + line + "\n"
            except java.lang.RuntimeException:
                print "RuntimeException"

        for api in self.riskAPIs.keys():
            if self.riskAPIs[api] :
                print "\n-", api
                print self.riskAPIs[api]