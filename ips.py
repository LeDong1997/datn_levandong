import sys, os
import psutil
import random
import numpy as np
import time
import subprocess
import json
import socket
import struct
import threading
import random
import webbrowser
import math
import datetime
import requests

import win32ui
import win32gui
import win32con
import win32api

from time import sleep,mktime,strftime
from json.decoder import JSONDecoder
from PyQt5.Qt import Qt, QFont
from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import pyqtSlot, QTimeLine, pyqtSignal, QThread
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QAction, QLineEdit, QMessageBox, QTableWidgetItem, QAbstractItemView, QMessageBox
from PyQt5.QtChart import QChart, QChartView, QValueAxis, QBarCategoryAxis, QBarSet, QBarSeries, QLineSeries
from PyQt5.QtGui import QPainter, QPixmap
from mplwidget import*
from subprocess import check_output as qx

 
qtCreatorFile = "ips.ui" # Enter file here.
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)
Ui_MainWindowLoading, QtBaseClassLoading = uic.loadUiType("loading.ui")

passwordCrpyt = ""
eventCrypt = ""
pathCrypt = ""

class LoadingApp(QMainWindow, Ui_MainWindowLoading, QWidget):
    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindowLoading.__init__(self)
        self.setupUi(self)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.screenShape = QDesktopWidget().screenGeometry()
        self.setFixedSize(self.screenShape.width(), self.screenShape.height())
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        app = openMainWindow(self)
        app.exitLoading.connect(self.exitLoading)
        app.start()
        app.exec_()
        sys.exit(app.exec_())

    def exitLoading(self):
        self.app = MyApp()
        self.app.show()
        self.close()


class openMainWindow (QThread):
    exitLoading = pyqtSignal()
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        time.sleep(0.5)
        self.exitLoading.emit()


		
class MyApp(QMainWindow, Ui_MainWindow, QWidget):

    def fcntl(fd, op, arg=0):
        return 0

    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)

        self.setupUi(self)
        self.setFixedSize(956, 672)
        self.setWindowTitle("Host based IPS")
        self.setWindowIcon(QtGui.QIcon("icon/logo_ips.png"))
        self.styleTable()
        self.baseLink()
        self.integrity()

        # -----------------chart Threads ------------------#


        runThreadscanIntegrity = ThreadscanIntegrity(self)
        runThreadscanIntegrity.updateReportScan.connect(self.reportScan)
        runThreadscanIntegrity.start()

        runThreadscanMonitor = ThreadscanMonitor(self)
        runThreadscanMonitor.start()




    def baseLink(self):
        self.button_detail.clicked.connect(lambda: webbrowser.open('https://dascam.com.vn'))

        self.backHome1.mouseReleaseEvent=self.changeTabTo0
        self.backHome2.mouseReleaseEvent=self.changeTabTo12
        self.backHome3.mouseReleaseEvent=self.changeTabTo0
        self.backHome8.mouseReleaseEvent=self.changeTabTo0
        self.backHome10.mouseReleaseEvent=self.changeTabTo0
        self.backHome12.mouseReleaseEvent=self.changeTabTo0
        self.backHome13.mouseReleaseEvent=self.changeTabTo0

        # Change Host IPS tab
        self.function1.mouseReleaseEvent=self.changeTabTo4
        self.function2.mouseReleaseEvent=self.changeTabTo12
        self.function3.mouseReleaseEvent=self.changeTabTo13
        self.function6.mouseReleaseEvent=self.changeTabTo1
        self.function4.mouseReleaseEvent=self.changeTabTo8
        self.function5.mouseReleaseEvent=self.changeTabTo10

        #click disk detail 
        self.disk_detail.mouseReleaseEvent=self.changeTabTo2

 

        #change file sytem protect tab 
        self.file_system.mouseReleaseEvent = self.changeTabTo5
        self.folder_system.mouseReleaseEvent = self.changeTabTo15
        self.back_file_system.mouseReleaseEvent = self.changeTabTo4
        self.back_file_system_2.mouseReleaseEvent = self.changeTabTo4
        self.back_file_system_3.mouseReleaseEvent = self.changeTabTo4
        self.integrity_check.mouseReleaseEvent = self.changeTabTo6
        self.Monitor_file_system.mouseReleaseEvent= self.changeTabTo14
        self.back_file_system_4.mouseReleaseEvent= self.changeTabTo4
        self.progressBar_folder.hide()
        self.alert_hash.hide()
        self.log_reports.mouseReleaseEvent= self.changeTabTo16
        self.log_reports_monitor.mouseReleaseEvent = self.showTableReportMonitor
        self.back_integrity.mouseReleaseEvent = self.changeTabTo6
        self.remove_file.clicked.connect(self.removePath)
        self.update_file.clicked.connect(self.updatePath)
        self.remove_file_monitor.clicked.connect(self.removePathMonitor)
        self.update_file_monitor.clicked.connect(self.updatePathMonitor)


        #tab report
        self.back_to_report.mouseReleaseEvent=self.changeReportToMain
        self.change_show_report_list.mouseReleaseEvent=self.showReprotList
        self.show_table_report_monitor.mouseReleaseEvent=self.showTableReportMonitor
        self.back_to_report_2.mouseReleaseEvent=self.changeReportToMain
        self.show_table_report_integrity.mouseReleaseEvent=self.showTableReportIntegrity
        self.back_to_report_3.mouseReleaseEvent=self.changeReportToMain
        self.back_to_report_4.mouseReleaseEvent=self.changeReportToMain
        self.filter_day.mouseReleaseEvent=self.updateTablebyFilter
        self.filter_day_monitor.mouseReleaseEvent=self.updateTableMonitorbyFilter


        #scan file
        self.import_file.mouseReleaseEvent=self.scanFile
        self.box_function.toggled.connect(self.changeState)
        #star_encrypt_file
        self.start_crypt.clicked.connect(lambda: self.startCrypt(self.file_info.toPlainText()))
        #scan folder
        self.import_folder.mouseReleaseEvent=self.scanFolder
        self.box_function_2.toggled.connect(self.changeStateFolder)
        #star_encrypt_file
        self.start_crypt_folder.clicked.connect(lambda: self.startCryptFolder(self.folder_info.toPlainText()))
        #improt file/folder/xml/hashFile intergitry
        self.select_file.mouseReleaseEvent = self.addFile
        self.select_folder.mouseReleaseEvent = self.addFolder
        self.select_file_xml.mouseReleaseEvent = self.addXml
        self.select_hash.mouseReleaseEvent=self.hashFile
        self.hash.hide()
        self.code_hash.hide()
        #improt file/folder monitor
        self.select_file_monitor.mouseReleaseEvent = self.addFileMonitor
        self.select_folder_monitor.mouseReleaseEvent = self.addFolderMonitor


    # ================================== functions of system =====================================#
    def changeTabTo0(self, instance):
        # FaderWidget(self.main.currentWidget(),self.main.widget(0))
        self.main.setCurrentIndex(0)
    def changeTabTo1(self, instance):
        # FaderWidget(self.main.currentWidget(),self.main.widget(1))
        self.main.setCurrentIndex(1)
    
    def changeTabTo2(self, instance):
        self.main.setCurrentIndex(2)
    def changeTabTo3(self, instance):
        self.main.setCurrentIndex(3)
        self.clearDataInputInRule()
    def changeTabTo4(self, instance):
        self.main.setCurrentIndex(4)
    def changeTabTo5(self, instance):
        self.main.setCurrentIndex(5)
    def changeTabTo6(self,instance):
        self.main.setCurrentIndex(6)
    def changeTabTo7(self, instance):
        self.main.setCurrentIndex(7)
        self.clearDataInputOutRule()
    def changeTabTo8(self, instance):
        self.main.setCurrentIndex(8)
    def changeTabTo9(self, instance):
        self.main.setCurrentIndex(9)
    def changeTabTo10(self, instance):
        self.main.setCurrentIndex(10)
    def changeTabTo12(self, instance):
        self.main.setCurrentIndex(12)
    def changeTabTo13(self, instance):
        self.main.setCurrentIndex(13)
    def changeTabTo14(self, instance):
        self.main.setCurrentIndex(14)
    def changeTabTo15(self, instance):
        self.main.setCurrentIndex(15)
    def changeTabTo16(self, instance):
        self.main.setCurrentIndex(16)
        self.showDetailReportIntegrity()
    def changeTabTo17(self, instance):
        self.main.setCurrentIndex(17)
    def changeTabTo18(self, instance):
        self.main.setCurrentIndex(18)
    def changeTabTo19(self, instance):
        self.main.setCurrentIndex(19)
    def changeTabTo20(self, instance):
        self.main.setCurrentIndex(20)
        self.clearDataProgramRule()
    def changeTabTo21(self, instance):
        self.main.setCurrentIndex(21)
    def changeTabTo22(self, instance):
        self.main.setCurrentIndex(22)
    def changeTabTo23(self, instance):
        self.main.setCurrentIndex(23)
    def changeTabTo24(self, instance):
        self.main.setCurrentIndex(24)
    def changeTabTo25(self, instance):
        self.main.setCurrentIndex(25)


    def changeReportToMain(self, instance):
        self.main.setCurrentIndex(10)
    def showReprotList(self,instance):
        self.main.setCurrentIndex(11)

    

    def integrity(self):
        self.showPathTable()
        self.updatePathMonitor()

    # def closeEvent(self, event):
    #     sys.exit()


    
    # ================================== end functions of system =====================================#






    @pyqtSlot()

    ############################################### File system protection #######################################################
    # =============================================file system================================================================#

    def scanFile(self, instance):
        option = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)

        if fileName:
            self.file_system_protection.setCurrentIndex(0)
            self.message_scan.setVisible(False)
            self.select_function.setText("Thực hiện mã hóa")
            self.file_info.setText(fileName)

    def changeState(self):
        if self.box_function.isChecked():
            self.select_function.setText("Thực hiện giải hóa")
        else:
            self.select_function.setText("Thực hiện mã hóa")


    def startCrypt(self, path):
        path = path.replace("/","\\")
        self.message_scan.setVisible(False)
        password = self.confirmPassword()
        if password == "canceled":
            self.start_crypt_folder.setEnabled(True)
            return
        else:
            # cmd = ''
            if self.box_function.isChecked():
                self.decryptFile(path, password, 0)
            else:
                cmd = 'python crypto.py -e -f ' '"'+path+'"' + ' "'+password+'"'
                self.encryptFile(cmd)


    def encryptFile(self, cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        state = str(output).find("Done encrypt file")
        # print(str(output), state)
        if state != -1:   
            self.message_scan.setVisible(True)
            self.message_scan.setText("Mã hóa thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/check.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");
        else:
            self.message_scan.setVisible(True)
            self.message_scan.setText("Mã hóa không thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/unnamed.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");


    def decryptFile(self, path, password, Option):
        cmd = 'python crypto.py -d -f ' '"'+path+'"' + ' "'+password+'"'+' '+str(Option)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        state = str(output).find("Done decrypt file.")
        print(str(output), state)
        if state != -1:   
            self.message_scan.setVisible(True)
            self.message_scan.setText("Giải mã thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/check.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");
        elif(str(output).find("Confirm override") != -1):
            status = self.confirmBox("Tệp tin giải mãi đã tồn tại, bạn có muốn ghi đè?")
            if(status == 1):
                self.decryptFile(path, password, 2)
        else:
            self.message_scan.setVisible(True)
            self.message_scan.setText("Giải mã không thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/unnamed.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");


    def confirmPassword(self):
        dlg = QInputDialog()
        text, result = dlg.getText(self, "Nhập mật khẩu",
                                     "New password:", QLineEdit.Normal)

        if result and text:
            return text
        else:
            return "canceled"


    def confirmBox(self, mess):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(mess)
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msg.setWindowFlags(QtCore.Qt.CustomizeWindowHint)
        ret = retval = msg.exec_()
        if ret == QMessageBox.Ok:
            return 1
        else:
            return 0



    # =============================================folder system================================================================#
                      

    def scanFolder(self, instance):
        option = QFileDialog.Options()
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory",
                                             "/home",
                                             QFileDialog.ShowDirsOnly
                                             | QFileDialog.DontResolveSymlinks)

        if folderName:
            self.message_scan_2.setVisible(False)
            self.select_function_2.setText("Thực hiện mã hóa")
            self.folder_info.setText(folderName)

    def changeStateFolder(self):
        if self.box_function_2.isChecked():
            self.select_function_2.setText("Thực hiện giải mã")
        else:
            self.select_function_2.setText("Thực hiện mã hóa")

    def startCryptFolder(self, path):
        self.message_scan_2.setVisible(False)
        self.start_crypt_folder.setEnabled(False)
        password = self.confirmPassword()
        path = path.replace("/","\\")
        if password == "canceled":
            self.start_crypt_folder.setEnabled(True)
            return
        else:
            cmd = ''
            global pathCrypt
            global eventCrypt
            global passwordCrpyt
            if self.box_function_2.isChecked():
                event = "decode"
            else:
                event = "encode"
            pathCrypt = path
            eventCrypt = event
            passwordCrpyt = password
            self.path_crypt.setText("")
            self.progressBar_folder.setValue(0)
            self.progressBar_folder.setVisible(True)
            self.message_scan_2.setVisible(True)
            self.progressBar_folder.setMaximum(100)
            self.message_scan_2.setIcon(QtGui.QIcon())
            runThreadEncryptFolder = ThreadEncryptFolder(self)
            runThreadEncryptFolder.updatePath.connect(self.path_crypt.setText)
            runThreadEncryptFolder.updateProcessBar.connect(self.progressBar_folder.setValue)
            runThreadEncryptFolder.updateIndex.connect(self.message_scan_2.setText)
            runThreadEncryptFolder.completeCrypt.connect(self.completeCryptFolder)
            runThreadEncryptFolder.start()

    def completeCryptFolder(self):
        self.progressBar_folder.setValue(100)
        self.message_scan_2.setIcon(QtGui.QIcon("icon/check.png"))
        self.start_crypt_folder.setEnabled(True)


    # =============================================Kiem tra tinh toan ven ================================================================#

    def addFile(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_file.setText(fileName)
            cmd = 'python demo_integrity.py -i ' + '"'+fileName+'"' +' 0'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTable()


    def addFolder(self, instance):
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory","/home",QFileDialog.ShowDirsOnly|QFileDialog.DontResolveSymlinks)
        if folderName:
            self.path_folder.setText(folderName)
            cmd = 'python demo_integrity.py -i ' + '"'+folderName+'"' +' 1'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTable()


    def addXml(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','*.xml',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_xml.setText(fileName)
            cmd = 'python demo_integrity.py -x ' + '"'+fileName+'"'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTable()

    def hashFile(self, instance):
        self.alert_hash.hide()
        self.hash.hide()
        self.code_hash.hide()
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_hash_file.setText(fileName)
            cmd = 'python demo_integrity.py -m ' + '"'+fileName+'"'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                state = json.loads(output.decode('ASCII'))['result']
                data = json.loads(output.decode('ASCII'))['hash_str']
                if(state == True):
                    self.alert_hash.setVisible(True)
                    self.hash.setVisible(True)
                    self.code_hash.setVisible(True)
                    self.code_hash.setText(data)

                else:
                    self.alert_hash.setIcon(QtGui.QIcon("icon/unnamed.png"))
                    self.alert_hash.setText("Không thành công")



    def showPathTable(self):
        cmd = 'python demo_integrity.py -l'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        if(p_status == 0):
            data = json.loads(output.decode('ASCII'))['check_list']
            self.path_list.setColumnCount(2)
            self.path_list.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[2])
                self.path_list.setCellWidget(i,0,path)
                self.path_list.setItem(i, 1, QTableWidgetItem(str(data[1])))
                i = i + 1
            self.path_list.setColumnHidden(1, True)


    def removePath(self):
        indexes = self.path_list.selectionModel().selectedRows()
        for index in sorted(indexes):
            path = self.path_list.cellWidget(index.row(), 0).text()
            Type = self.path_list.item(index.row(), 1).text()
            cmd = 'python demo_integrity.py -r '+'"'+path+'"' +' '+Type
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
        self.showPathTable()

    def updatePath(self):
        self.showPathTable()

    def showDetailReportIntegrity(self):
        layout = QGridLayout()
        try:
            layout = self.scrollArea_intefrity.findChild(QLayout,"report_integrity_list")
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                  child.widget().deleteLater()
        except Exception as e:
            layout = QGridLayout(self.list_report_integrity)
            layout.setObjectName("report_integrity_list") 
        cmd = 'python demo_integrity.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = json.loads(output.decode('ASCII'))['alert_list']

        i = 0
        for data in data:
            widget = QWidget()
            widget.setStyleSheet("QWidget {background: rgba(255,255,255,0.1); border-radius: 5px;} QLabel{background: transparent;} QWidget:hover {background: rgba(255,255,255,0.2);} QLabel:hover {background: transparent}")
            widget.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
            widget.setObjectName(str(i)+"||widget_report")
            widget.setFixedHeight(65)
            name = QLabel(data[3])
            name.setObjectName(str(i)+"||label_name_report")
            status = QLabel(data[2])
            status.setObjectName(str(i)+"||label_status_report")
            status.setStyleSheet("QLabel {color: #72ac57}")
            timeReport = QLabel(data[1])
            timeReport.setObjectName(str(i)+"||label_time_report")
            timeReport.setAlignment(Qt.AlignCenter | Qt.AlignRight);
            
            layoutItem = QGridLayout(widget)
            layoutItem.addWidget(name, 0, 0)
            layoutItem.addWidget(timeReport, 0, 1)
            layoutItem.addWidget(status, 1, 0)
            layout.addWidget(widget, i, 0)
            i=i+1
            if(i == 100):
                break


    def reportScan(self):
        cmd = 'python demo_integrity.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = json.loads(output.decode('ASCII'))['alert_list']
        i = 0
        for data in data:
            if(i == 0):
                self.path_integrity_1.setText(data[3])
                self.status_integrity_1.setText(data[2])
                self.status_integrity_1.setStyleSheet("QLabel {color: #72ac57}")
                self.time_report_integrity_1.setText(data[1])
            elif( i == 1):
                self.path_integrity_2.setText(data[3])
                self.status_integrity_2.setText(data[2])
                self.status_integrity_2.setStyleSheet("QLabel {color: #72ac57}")
                self.time_report_integrity_2.setText(data[1])
            else:
                self.path_integrity_3.setText(data[3])
                self.status_integrity_3.setText(data[2])
                self.status_integrity_3.setStyleSheet("QLabel {color: #72ac57}")
                self.time_report_integrity_3.setText(data[1])
            i = i + 1
            if(i == 3):
                break




    # =============================================Giám sát tệp tin, thư mục ================================================================#

    def addFileMonitor(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            fileName = fileName.replace("/","\\")
            self.path_file_monitor.setText(fileName)
            cmd = 'python demo_monitor.py -i ' + '"'+fileName+'"' +' 0'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            print(str(output), 123)
            if(p_status == 0):
                self.showPathTableMonitor()



    def addFolderMonitor(self, instance):
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory","/home",QFileDialog.ShowDirsOnly|QFileDialog.DontResolveSymlinks)
        if folderName:
            folderName = folderName.replace("/","\\")
            self.path_folder.setText(folderName)
            cmd = 'python demo_monitor.py -i ' + '"'+folderName+'"' +' 1'
            print(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            print(str(output), "1234")
            if(p_status == 0):
                self.showPathTableMonitor()


    def showPathTableMonitor(self):
        cmd = 'python demo_monitor.py -l'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = json.loads(output.decode('ASCII'))['check_list']
        if(p_status == 0):
            self.path_list_monitor.setColumnCount(2)
            self.path_list_monitor.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[2])
                self.path_list_monitor.setCellWidget(i,0,path)
                self.path_list_monitor.setItem(i, 1, QTableWidgetItem(str(data[1])))
                i = i + 1
            self.path_list_monitor.setColumnHidden(1, True)


    def removePathMonitor(self):
        indexes = self.path_list_monitor.selectionModel().selectedRows()
        for index in sorted(indexes):
            path = self.path_list_monitor.cellWidget(index.row(), 0).text()
            Type = self.path_list_monitor.item(index.row(), 1).text()
            cmd = 'python demo_monitor.py -r '+'"'+path+'"' +' '+Type
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
        self.showPathTableMonitor()


    def updatePathMonitor(self):
        self.showPathTableMonitor()
        self.reportScanMonitor()
        self.update_file_monitor.setText("Cập nhật")


    def reportScanMonitor(self):
        cmd = 'python demo_monitor.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.report_table.setColumnCount(5)
            self.report_table.setRowCount(len(data))
            i = 0
            for data in data:
                self.report_table.setItem(i, 0, QTableWidgetItem(data[1]))
                self.report_table.setItem(i, 1, QTableWidgetItem(data[2]))
                self.report_table.setItem(i, 2, QTableWidgetItem(data[3]))
                self.report_table.setItem(i, 3, QTableWidgetItem(data[4]))
                self.report_table.setItem(i, 4, QTableWidgetItem(data[5]))
                self.report_table.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                i = i + 1
                if(i == 100):
                    break
        except Exception as e:
            print(e)



            


    ############################################### End file system protection #######################################################



    ################################################# REPORT  ###################################################################


    def showTableReportMonitor(self, instance):
        self.main.setCurrentIndex(23)
        cmd = 'python demo_monitor.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.table_report_monitor.setColumnCount(5)
            self.table_report_monitor.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/folder.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[5])
                self.table_report_monitor.setItem(i, 0, QTableWidgetItem(data[1]))
                self.table_report_monitor.setItem(i, 1, QTableWidgetItem(data[2]))
                self.table_report_monitor.setItem(i, 2, QTableWidgetItem(data[3]))
                self.table_report_monitor.setItem(i, 3, QTableWidgetItem(data[4]))
                self.table_report_monitor.setCellWidget(i,4,path)
                self.table_report_monitor.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                i = i + 1
        except Exception as e:
            print(e)

    
    def updateTableMonitorbyFilter(self, instance):
        self.table_report_monitor.clear()
        self.table_report_monitor.setHorizontalHeaderItem(0, QTableWidgetItem("Thời gian"))
        self.table_report_monitor.setHorizontalHeaderItem(1, QTableWidgetItem("Người dùng"))
        self.table_report_monitor.setHorizontalHeaderItem(2, QTableWidgetItem("Máy trạm"))
        self.table_report_monitor.setHorizontalHeaderItem(3, QTableWidgetItem("Hành vi"))
        self.table_report_monitor.setHorizontalHeaderItem(4, QTableWidgetItem("Tài nguyên"))

        cmd = 'python demo_monitor.py -a_7'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.table_report_monitor.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/folder.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[5])
                self.table_report_monitor.setItem(i, 0, QTableWidgetItem(data[1]))
                self.table_report_monitor.setItem(i, 1, QTableWidgetItem(data[2]))
                self.table_report_monitor.setItem(i, 2, QTableWidgetItem(data[3]))
                self.table_report_monitor.setItem(i, 3, QTableWidgetItem(data[4]))
                self.table_report_monitor.setCellWidget(i,4,path)
                self.table_report_monitor.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                i = i + 1
        except Exception as e:
            print(e)



    def showTableReportIntegrity(self, instance):
        self.main.setCurrentIndex(24)
        cmd = 'python demo_integrity.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.table_report_integrity.setColumnCount(3)
            self.table_report_integrity.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/folder.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[3])
                self.table_report_integrity.setCellWidget(i,0,path)
                self.table_report_integrity.setItem(i, 1, QTableWidgetItem(data[2]))
                self.table_report_integrity.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                self.table_report_integrity.setItem(i, 2, QTableWidgetItem(data[1]))
                i = i + 1
        except Exception as e:
            print(e)


    def updateTablebyFilter(self, instance):
        self.table_report_integrity.clear()
        self.table_report_integrity. setHorizontalHeaderItem(0, QTableWidgetItem("Tệp tin/Thư mục"))
        self.table_report_integrity. setHorizontalHeaderItem(1, QTableWidgetItem("Hành Động"))
        self.table_report_integrity. setHorizontalHeaderItem(2, QTableWidgetItem("Thời gian"))
        cmd = 'python demo_integrity.py -l_7'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.table_report_integrity.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/folder.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[3])
                self.table_report_integrity.setCellWidget(i,0,path)
                self.table_report_integrity.setItem(i, 1, QTableWidgetItem(data[2]))
                self.table_report_integrity.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                self.table_report_integrity.setItem(i, 2, QTableWidgetItem(data[1]))
                i = i + 1
        except Exception as e:
            print(e)





    ############################################# end REPORT #######################################################



    def styleTable(self):
        # Hide left-header of table
        self.report_table.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.report_table.setSortingEnabled(True) 
        # Disable editing of cell
        self.report_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.report_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.report_table.setShowGrid(False)
        self.report_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.report_table.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.report_table.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.path_list.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.path_list.setSortingEnabled(True) 
        # Disable editing of cell
        self.path_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.path_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.path_list.setShowGrid(False)
        self.path_list.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.path_list.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.path_list.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.path_list_monitor.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.path_list_monitor.setSortingEnabled(True) 
        # Disable editing of cell
        self.path_list_monitor.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.path_list_monitor.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.path_list_monitor.setShowGrid(False)
        self.path_list_monitor.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.path_list_monitor.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.path_list_monitor.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.list_file_scan.verticalHeader().setVisible(False)
        # Hide top-header of table
        self.list_file_scan.horizontalHeader().setVisible(False)
        # Sort by row when click header
        self.list_file_scan.setSortingEnabled(True) 
        # Disable editing of cell
        self.list_file_scan.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.list_file_scan.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.list_file_scan.setShowGrid(False)
        self.list_file_scan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.list_file_scan.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.list_file_scan.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        

        # Hide left-header of table
        self.table_report_monitor.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_report_monitor.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_report_monitor.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_report_monitor.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_report_monitor.setShowGrid(False)
        #set full width and height for table 
        self.table_report_monitor.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_report_monitor.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)


        # Hide left-header of table
        self.table_report_integrity.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_report_integrity.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_report_integrity.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_report_integrity.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_report_integrity.setShowGrid(False)
        #set full width and height for table 
        self.table_report_integrity.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_report_integrity.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)


        


class ThreadEncryptFolder (QThread):
    updatePath = pyqtSignal(str)
    updateProcessBar = pyqtSignal(int)
    updateIndex = pyqtSignal(str)
    completeCrypt = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        global eventCrypt
        global passwordCrpyt
        global pathCrypt
        self.path=pathCrypt
        self.password=passwordCrpyt
        self.event=eventCrypt


    def run(self):
        self.name = "thread_Encrypt_folder"

        count = 0
        for r, d, f in os.walk(self.path):
            for file in f:
                count=count+1

        totalFile = count
        i = 0
        succ = 0

        if(self.event == "encode"):
            for r, d, f in os.walk(self.path):
                for file in f:
                    filePath = os.path.join(r, file)
                    self.updatePath.emit("Tệp tin: "+filePath)
                    try:
                        cmd = 'python crypto.py -e -f ' '"'+filePath+'"' + ' "'+self.password+'"'
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()
                        state = str(output).find("Done encrypt file")
                        if state != -1:
                            self.updateProcessBar.emit(int(i*(100/totalFile))) 
                            succ=succ+1
                            self.updateIndex.emit("Mã hóa thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                        else:
                            self.updateProcessBar.emit(int(i*(100/totalFile)))
                            self.updateIndex.emit("Mã hóa thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                            print(f+" file encryption failed")

                    except Exception as e:
                        self.updateProcessBar.emit(int(i*(100/totalFile)))
                        self.updateIndex.emit("Mã hóa thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                        print(e)
                        i = i + 1
            self.completeCrypt.emit()
        else:
            for r, d, f in os.walk(self.path):
                for file in f:
                    filePath = os.path.join(r, file)
                    self.updatePath.emit("Tệp tin: "+filePath)
                    try:
                        cmd = 'python crypto.py -d -f ' '"'+filePath+'"' + ' "'+self.password+'"'+' 2'
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()
                        state = str(output).find("Done decrypt file")
                        if state != -1:
                            self.updateProcessBar.emit(int(i*(100/totalFile)))  
                            succ=succ+1
                            self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                        else:
                            self.updateProcessBar.emit(int(i*(100/totalFile)))
                            self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                            print(f+" file decryption failed")

                    except Exception as e:
                        self.updateProcessBar.emit(int(i*(100/totalFile)))
                        self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                        print(e)
                        i = i + 1
            self.completeCrypt.emit()



class ThreadscanIntegrity (QThread):
    updateReportScan = pyqtSignal()
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
    def run(self):
        while(True):
            # lay danh sach tep tin/thu muc kiem tra tinh toan ven
            cmd = 'python demo_integrity.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            # Vong lap quet tung tep tin/ thu muc
            if(p_status == 0):
                data = json.loads(output.decode('ASCII'))['check_list']
                for d in data:
                    cmd = 'python demo_integrity.py -s ' + '"'+d[2]+'"'+" "+str(d[1])
                    print(cmd)
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()
                    print(output)
            self.updateReportScan.emit()
            time.sleep(60)





class ThreadscanMonitor (threading.Thread):
    def __init__(self, window):
        threading.Thread.__init__(self)
        self.window=window
    def run(self):
        while(True):
            # lay danh sach tep tin/thu muc theo doi
            cmd = 'python demo_monitor.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            # Vong lap quet tung tep tin/ thu muc
            if(p_status == 0):
                data = json.loads(output.decode('ASCII'))['check_list']
                for d in data:
                    cmd = 'python demo_monitor.py -s ' + '"'+d[2]+'"'+" "+str(d[1])
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()

            time.sleep(3600)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont()
    font.setPixelSize(13);
    font.setFamily(font.defaultFamily())
    app.setFont(font)
    window = LoadingApp()
    window.show()

    sys.exit(app.exec_())

