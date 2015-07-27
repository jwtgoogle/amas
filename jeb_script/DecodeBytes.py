import os
import jeb
from jeb.api import IScript
from jeb.api.ast import Constant
from jeb.api.dex import Dex
from jeb.api.ui import JebUI, View
from jeb.api.ui.JebUI import ButtonGroupType
from jeb.api.ui.JebUI import IconType
from jeb.api.ast import Method, Block, Return, ConditionalExpression, New, Call, Constant, DoWhileStm, ForStm, IfStm, SwitchStm
from jeb.api.ast import TryStm, WhileStm, Identifier, Expression, TypeReference, StaticField, InstanceField, ArrayElt, Assignment, NewArray

import java.lang.System

# TODO 可以JPython 直接引入这个apk的Jar，获取当前类方法，解密函数？

class DecodeBytes(IScript):

    def run(self, jeb):
        self.jeb = jeb
        self.dex = self.jeb.getDex()
        self.classSignatures = self.dex.getClassSignatures(True)

        self.ui = jeb.getUI()

        self.cstBuilder = Constant.Builder(self.jeb)

        self.decodes = []

        for classSignature in self.classSignatures:
            try:
                if "/R;" in classSignature or "/R$" in classSignature or "/BuildConfig;" in classSignature:
                    continue
                javaCode = self.jeb.decompileClass(classSignature)
                # print javaCode
                decompileClass = self.jeb.getDecompiledClassTree(
                    classSignature)

                if decompileClass:
                    self.decodeNewByte(decompileClass)
                    print "\n\n =============================== \n\n"
                    self.decodeMethod(decompileClass)
            except java.lang.RuntimeException:
                print "RuntimeException"

        self.ui.getView(View.Type.ASSEMBLY).refresh()
        self.ui.getView(View.Type.JAVA).refresh()
        self.ui.getView(View.Type.CLASS_HIERARCHY).refresh()

    def decodeNewByte(self, c):
        '''
            decode static byte[] bytes = new byte[]{47, 47, 122, 104, 105)
        '''
        fields = c.getFields()
        self.handleFields(fields, c)

    def handleFields(self, mFields, mClass):
        print('handle fields')
        ifReByStc = False
        # walk through fields
        for f in mFields:
            sig = f.getSignature()
            print "field signature : ", sig
            if sig.endswith('[B'):
                # sig => fieldData => index => Reference
                fieldData = self.dex.getFieldData(sig)
                accessFlag = fieldData.getAccessFlags()
                wanted_flags = Dex.ACC_STATIC | Dex.ACC_FINAL
                if not accessFlag & wanted_flags:
                    return
                fieldIdx = fieldData.getFieldIndex()
                self.referIdx = self.dex.getFieldReferences(fieldIdx)
                for referIdx in self.referIdx:
                    method = self.dex.getMethod(referIdx)
                    self.referName = method.getName(False)
                    m_sig = method.getSignature(False)
                    if m_sig.endswith('<clinit>()V'):
                        ifReByStc = True
                        break
            if ifReByStc:
                break
        if not ifReByStc:
            return

        for method_a in mClass.getMethods():
            if method_a.getName() == '<clinit>':
                print('Turn ByteArray to String here...')
                '''
                handle form : byte[] a = new byte{0x23,0x24..}; b = new String(a)
                some byte array used for decode may be handled too, but doesn't matter
                '''
                self.handleCInit(method_a)
                # continue
                break

        print "\n\n decode new String(new byte{}) ......"
        ifReByStc = False
        for f in mFields:
            sig = f.getSignature()
            if sig.endswith('Ljava/lang/String;'):
                print "Signature ", sig
                # sig => fieldData => index => Reference
                fieldData = self.dex.getFieldData(sig)
                print "fieldData", fieldData
                accessFlag = fieldData.getAccessFlags()
                print "accessFlag", accessFlag
                wanted_flags = Dex.ACC_STATIC | Dex.ACC_FINAL
                if not accessFlag & wanted_flags:
                    return
                fieldIdx = fieldData.getFieldIndex()
                print "fieldIdx", fieldIdx
                self.referIdx = self.dex.getFieldReferences(fieldIdx)
                for referIdx in self.referIdx:
                    method = self.dex.getMethod(referIdx)
                    self.referName = method.getName(False)
                    print "referName", self.referName
                    m_sig = method.getSignature(False)
                    if m_sig.endswith('<clinit>()V'):
                        ifReByStc = True
                        print ""
                        break
            # if ifReByStc:
                # break
        if not ifReByStc:
            return
        for method_a in mClass.getMethods():
            if method_a.getName() == '<clinit>':
                print('Turn ByteArray to String here...')
                '''
                handle form : byte[] a = new byte{0x23,0x24..}; b = new String(a)
                some byte array used for decode may be handled too, but doesn't matter
                '''
                self.handleCInit2(method_a)
                # continue
                break

    def handleCInit(self, cinit):
        # print( 'handle CInit...')
        methodBody = cinit.getBody()
        count = methodBody.size()
        i = 0
        while i < count:
            method_a = methodBody.get(i)
            print "method_a", method_a
            try:
                if isinstance(method_a, jeb.api.ast.Assignment):
                    self.handleAssignment_StaticFieldDecode(method_a)
                i += 1
            except java.lang.IllegalStateException:
                print('illegal exception')
                i += 1
                continue

    def handleCInit2(self, cinit):
        # print( 'handleCInit2...')
        methodBody = cinit.getBody()
        count = methodBody.size()
        i = 0
        while i < count:
            method_a = methodBody.get(i)
            print "method_a", method_a
            try:
                if isinstance(method_a, jeb.api.ast.Assignment):
                    self.handNewString(method_a)
                i += 1
            except java.lang.IllegalStateException:
                print('illegal exception')
                i += 1
                continue

    def handNewString(self, mAssignment):
        print('\n handle handNewString...')
        left = mAssignment.getLeft()
        print('left type :' + str(type(left)))
        right = mAssignment.getRight()
        print('right type :' + str(type(right)), right.getType())
        message = ''
        print('message before: ' + message)
        if isinstance(left, jeb.api.ast.StaticField) and isinstance(right, jeb.api.ast.New):

    def handleNew(self, mNew):
        self.log_on('handle New')
        mType = mNew.getType()
        self.log_off('instance type : ' + str(mType))
        args = mNew.getArguments()
        self.log_off('args type : ' + str(type(args)))
        # 4 means [inside mehtod] new String(new byte[]{...})
        # if 4 in self.deMethodNO and args and
        # isinstance(args.get(0),jeb.api.ast.NewArray) and mType ==
        # 'Ljava/lang/String;' :
        self.log_off('<><><><>')
        self.handleNewString(mNew, args.get(0))

        if args:
            self.handleBlock(args)

    # new String(new byte[]{}) in method body
    def handleNewString(self, mNew, args):
        t = ''
        i = 0
        data = args.getInitialValues()
        if not data:
            return
        self.log_off(type(data))
        self.log_off('size of data : ' + str(data.size()))
        size = data.size()
        while i < size:
            self.log_off(type(data.get(i)))
            t += chr(data.get(i).getByte())

            i += 1
        self.log_off(t)
        subEle = mNew.getSubElements().get(1)
        self.log_off("subEle of ByteArray : " + str(type(subEle)))
        mNew.replaceSubElement(subEle, self.cstBuilder.buildString(t))

    def handleAssignment_StaticFieldDecode(self, mAssignment):
        print('\n handle Assignment...')
        left = mAssignment.getLeft()
        print('left type :' + str(type(left)))
        right = mAssignment.getRight()
        print('right type :' + str(type(right)))
        message = ''
        print('message before: ' + message)
        if isinstance(left, jeb.api.ast.StaticField) and isinstance(right, jeb.api.ast.NewArray):
            data = right.getInitialValues()
            if not data:
                return
            for v in data:
                # can turn to String
                if v.getByte() < 0:
                    return
                self.decodes.append(v.getByte())
            for v in self.decodes:
                message += unichr(v)
            print('message after :' + message)
            subEle = mAssignment.getSubElements().get(1)
            print("subEle of ByteArray : " + str(type(subEle)))
            mAssignment.replaceSubElement(
                subEle, self.cstBuilder.buildString(message))
            self.decodes = []

    def decodeMethod(self, c):
        methods = c.getMethods()
        for method_a in methods:
            print('method name ' + method_a.getName())
            methodBody = method_a.getBody()
            print methodBody
            print method_a.getParameters()

            # self.handleBlock(methodBody)
