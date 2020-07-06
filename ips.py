import sys
import os
# import psutil
# import random
# import numpy as np
import time
import subprocess
import json
# import socket
# import struct
import threading
# import random
import webbrowser
# import math
# import datetime
# import requests

# import win32ui
# import win32gui
# import win32con
# import win32api

# from time import sleep, mktime, strftime
# from json.decoder import JSONDecoder
from PyQt5.Qt import Qt, QFont
from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import pyqtSlot, QTimeLine, pyqtSignal, QThread
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QAction, QLineEdit, QMessageBox, \
    QTableWidgetItem, QAbstractItemView, QMessageBox
# from PyQt5.QtChart import QChart, QChartView, QValueAxis, QBarCategoryAxis, QBarSet, QBarSeries, QLineSeries
# from PyQt5.QtGui import QPainter, QPixmap
from mplwidget import *
# from subprocess import check_output as qx

qtCreatorFile = "ips.ui"  # Enter file here.
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)
Ui_MainWindowLoading, QtBaseClassLoading = uic.loadUiType("loading.ui")

# Global variable
passwordCrypt = ""
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
        app = OpenMainWindow(self)
        app.exitLoading.connect(self.exitLoading)
        app.start()
        app.exec_()
        sys.exit(app.exec_())

    def exitLoading(self):
        self.app = MyApp()
        self.app.show()
        self.close()


class OpenMainWindow(QThread):
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

        self.show_report_list()
        self.integrity()

        # -----------------Chart Threads------------------ #
        runThreadScanIntegrity = ThreadScanIntegrity(self)
        runThreadScanIntegrity.updateReportScan.connect(self.reportScan)
        runThreadScanIntegrity.start()

        runThreadScanMonitor = ThreadScanMonitor(self)
        runThreadScanMonitor.start()

        # -----------------Style Line Chart------------------ #
        self.chart_network.canvas.figure.set_facecolor("#121416")
        # self.chart_network.canvas.axes.patch.set_facecolor('black')
        self.chart_network.canvas.axes.patch.set_alpha(0.0)
        self.chart_network.canvas.axes.figure.set_facecolor('None')
        self.chart_network.canvas.axes.tick_params(labelcolor='#c7c7c9')
        self.chart_network.canvas.axes.set_xticklabels([])
        self.chart_network.canvas.axes.spines['top'].set_color('None')
        self.chart_network.canvas.axes.spines['left'].set_color('gray')
        self.chart_network.canvas.axes.spines['left'].set_alpha(0.2)
        self.chart_network.canvas.axes.spines['right'].set_color('None')
        self.chart_network.canvas.axes.spines['bottom'].set_color('gray')
        self.chart_network.canvas.axes.spines['bottom'].set_alpha(0.2)

        self.chart_cpu.canvas.figure.set_facecolor("#121416")
        self.chart_cpu.canvas.axes.patch.set_alpha(0.0)
        self.chart_cpu.canvas.axes.figure.set_facecolor('None')
        self.chart_cpu.canvas.axes.tick_params(labelcolor='#c7c7c9')
        self.chart_cpu.canvas.axes.spines['top'].set_color('None')
        self.chart_cpu.canvas.axes.spines['left'].set_color('gray')
        self.chart_cpu.canvas.axes.spines['left'].set_alpha(0.2)
        self.chart_cpu.canvas.axes.spines['right'].set_color('None')
        self.chart_cpu.canvas.axes.spines['bottom'].set_color('gray')
        self.chart_cpu.canvas.axes.spines['bottom'].set_alpha(0.2)

        self.chart_ram.canvas.figure.set_facecolor("#121416")
        self.chart_ram.canvas.axes.patch.set_alpha(0.0)
        self.chart_ram.canvas.axes.figure.set_facecolor('None')
        self.chart_ram.canvas.axes.tick_params(labelcolor='#c7c7c9')
        self.chart_ram.canvas.axes.spines['top'].set_color('None')
        self.chart_ram.canvas.axes.spines['left'].set_color('gray')
        self.chart_ram.canvas.axes.spines['left'].set_alpha(0.2)
        self.chart_ram.canvas.axes.spines['right'].set_color('None')
        self.chart_ram.canvas.axes.spines['bottom'].set_color('gray')
        self.chart_ram.canvas.axes.spines['bottom'].set_alpha(0.2)
        # -----------------End Style Line Chart------------------ #

    def baseLink(self):
        self.button_detail.clicked.connect(lambda: webbrowser.open('https://dascam.com.vn'))

        self.backHome1.mouseReleaseEvent = self.changeTabTo0
        self.backHome2.mouseReleaseEvent = self.changeTabTo12
        self.backHome3.mouseReleaseEvent = self.changeTabTo0
        self.backHome8.mouseReleaseEvent = self.changeTabTo0
        self.backHome10.mouseReleaseEvent = self.changeTabTo0
        self.backHome12.mouseReleaseEvent = self.changeTabTo0
        self.backHome13.mouseReleaseEvent = self.changeTabTo0

        # # Change Host IPS tab
        # self.function1.mouseReleaseEvent = self.changeTabTo4
        # self.function2.mouseReleaseEvent = self.changeTabTo12
        # self.function3.mouseReleaseEvent = self.changeTabTo13
        # self.function6.mouseReleaseEvent = self.changeTabTo1
        # self.function4.mouseReleaseEvent = self.changeTabTo8
        # self.function5.mouseReleaseEvent = self.changeTabTo10
        #
        # # click disk detail
        # self.disk_detail.mouseReleaseEvent = self.changeTabTo2

        # # Change network_management tab
        # self.firewall.mouseReleaseEvent = self.changeNetworkManagementTo_1
        # self.firewall_module_tab.mouseReleaseEvent = self.changeNetworkManagementTo_0
        # self.logManagement.mouseReleaseEvent = self.changeNetworkManagementTo_2
        # self.information.mouseReleaseEvent = self.changeNetworkManagementTo_3
        # self.rule_management.mouseReleaseEvent = self.changeNetworkManagementTo_4
        # # self.dns.mouseReleaseEvent=self.changeNetworkManagementTo_5
        # self.end_task.clicked.connect(self.killProcess)
        # self.end_task_2.clicked.connect(self.killProcessApp)
        #
        # # Change This PC tab
        # self.license.mouseReleaseEvent = self.changeThisPCTo_0
        # self.info_pc.mouseReleaseEvent = self.changeThisPCTo_1
        #
        # # rule management
        # self.rule_in.mouseReleaseEvent = self.changeTabTo17
        # self.rule_out.mouseReleaseEvent = self.changeTabTo18
        # self.rule_program.mouseReleaseEvent = self.changeTabTo19
        # self.back_rule_management.mouseReleaseEvent = self.changeTabTo1
        # self.back_rule_management_1.mouseReleaseEvent = self.changeTabTo1
        # self.back_rule_management_2.mouseReleaseEvent = self.changeTabTo1
        # self.back_to_inRule.mouseReleaseEvent = self.changeTabTo17
        # self.back_to_outRule.mouseReleaseEvent = self.changeTabTo18
        # self.back_to_programRule.mouseReleaseEvent = self.changeTabTo19
        # # click create new rule
        # self.add_rule_in.mouseReleaseEvent = self.changeTabTo3
        # self.add_rule_out.mouseReleaseEvent = self.changeTabTo7
        # self.add_rule_program.mouseReleaseEvent = self.changeTabTo20
        # self.create_in_rule.clicked.connect(self.createNewInRule)
        # self.create_out_rule.clicked.connect(self.createNewOutRule)
        # self.create_program_rule.clicked.connect(self.createNewProgramRule)
        # # restore new rule
        # self.restore_new_rule1.clicked.connect(self.clearDataInputInRule)
        # self.restore_new_rule2.clicked.connect(self.clearDataInputOutRule)
        # self.restore_new_rule3.clicked.connect(self.clearDataProgramRule)
        # # reomve rule
        # self.remove_rule.mouseReleaseEvent = self.removeRuleIn
        # self.remove_rule_out.mouseReleaseEvent = self.removeRuleOut
        # self.remove_rule_program.mouseReleaseEvent = self.removeRuleProgram
        # # change state rule
        # self.change_state_in.mouseReleaseEvent = self.changeStateInRule
        # self.change_state_out.mouseReleaseEvent = self.changeStateOutRule
        # self.change_state_program.mouseReleaseEvent = self.changeStateProgramRule

        # change file sytem protect tab
        self.file_system.mouseReleaseEvent = self.changeTabTo5
        self.folder_system.mouseReleaseEvent = self.changeTabTo15
        self.back_file_system.mouseReleaseEvent = self.changeTabTo4
        self.back_file_system_2.mouseReleaseEvent = self.changeTabTo4
        self.back_file_system_3.mouseReleaseEvent = self.changeTabTo4
        self.integrity_check.mouseReleaseEvent = self.changeTabTo6
        self.Monitor_file_system.mouseReleaseEvent = self.changeTabTo14
        self.back_file_system_4.mouseReleaseEvent = self.changeTabTo4
        self.progressBar_folder.hide()
        self.alert_hash.hide()
        self.log_reports.mouseReleaseEvent = self.changeTabTo16
        self.log_reports_monitor.mouseReleaseEvent = self.showTableReportMonitor
        self.back_integrity.mouseReleaseEvent = self.changeTabTo6
        self.remove_file.clicked.connect(self.removePath)
        self.update_file.clicked.connect(self.updatePath)
        self.remove_file_monitor.clicked.connect(self.removePathMonitor)
        self.update_file_monitor.clicked.connect(self.updatePathMonitor)

        # # change applications tab
        # self.application_1.mouseReleaseEvent = self.changeApplicationTo1
        # self.application_2.mouseReleaseEvent = self.changeApplicationTo2
        # self.application_3.mouseReleaseEvent = self.changeApplicationTo3
        # self.back_to_app.mouseReleaseEvent = self.changeTabTo8
        # self.show_security_hole.mouseReleaseEvent = self.showASecurityHole
        # self.back_to_application.mouseReleaseEvent = self.changeTabTo9
        # self.launch.mouseReleaseEvent = self.runApplication
        # self.remove_app.mouseReleaseEvent = self.removeApplication
        #
        # # change tab malware
        # self.full_scan.mouseReleaseEvent = self.changeMalwareTabTo0
        # self.quick_scan.mouseReleaseEvent = self.changeMalwareTabTo1
        # self.selective_scan.mouseReleaseEvent = self.changeMalwareTabTo2
        # self.external_device_scan.mouseReleaseEvent = self.changeMalwareTabTo3
        # # function quick scan
        # self.quick_scan_stop.hide()
        # self.quick_scan_end.hide()
        # self.info_quick_scan.hide()
        # self.quick_scan_stop.setEnabled(False)
        # self.quick_scan_end.setEnabled(False)
        # self.quick_scan_start.mouseReleaseEvent = self.quickScanStart
        # self.quick_scan_stop.mouseReleaseEvent = self.quickScanStop
        # self.quick_scan_end.mouseReleaseEvent = self.quickScanEnd
        # # function full scan
        # self.full_scan_stop.hide()
        # self.full_scan_end.hide()
        # self.info_full_scan.hide()
        # self.full_scan_stop.setEnabled(False)
        # self.full_scan_end.setEnabled(False)
        # self.full_scan_start.mouseReleaseEvent = self.fullScanStart
        # self.full_scan_stop.mouseReleaseEvent = self.fullScanStop
        # self.full_scan_end.mouseReleaseEvent = self.fullScanEnd
        # self.show_detail_full_scan.mouseReleaseEvent = lambda x: self.showListVirusScan("full_scan")
        # self.show_detail_quick_scan.mouseReleaseEvent = lambda x: self.showListVirusScan("quick_scan")
        # self.show_detail_selective_scan.mouseReleaseEvent = lambda x: self.showListVirusScan("selective_scan")
        # self.back_to_scan.mouseReleaseEvent = self.changeTabTo13
        # # import file/folder to scan
        # self.add_file_scan.mouseReleaseEvent = self.addFileScan
        # self.add_folder_scan.mouseReleaseEvent = self.addFolderScan
        # self.add_folder_scan_box.mouseReleaseEvent = self.addFolderScan
        # self.widget_scan.hide()
        # self.selective_scan_start.mouseReleaseEvent = self.selectiveScanStart
        # self.restore_list_path.hide()
        # self.restore_list_path.mouseReleaseEvent = self.restoreListPath
        # # remove virus
        # self.remove_virus.clicked.connect(self.removeVirus)

        # tab report
        self.back_to_report.mouseReleaseEvent = self.changeReportToMain
        self.change_show_report_list.mouseReleaseEvent = self.showReprotList
        self.show_table_report_monitor.mouseReleaseEvent = self.showTableReportMonitor
        self.back_to_report_2.mouseReleaseEvent = self.changeReportToMain
        self.show_table_report_integrity.mouseReleaseEvent = self.showTableReportIntegrity
        self.back_to_report_3.mouseReleaseEvent = self.changeReportToMain
        self.show_table_report_virus.mouseReleaseEvent = self.showTableReportVirus
        self.back_to_report_4.mouseReleaseEvent = self.changeReportToMain

        # scan file
        self.import_file.mouseReleaseEvent = self.scanFile
        self.box_function.toggled.connect(self.changeState)
        # star_encrypt_file
        self.start_crypt.clicked.connect(lambda: self.startCrypt(self.file_info.toPlainText()))
        # scan folder
        self.import_folder.mouseReleaseEvent = self.scanFolder
        self.box_function_2.toggled.connect(self.changeStateFolder)
        # star_encrypt_file
        self.start_crypt_folder.clicked.connect(lambda: self.startCryptFolder(self.folder_info.toPlainText()))
        # improt file/folder/xml/hashFile intergitry
        self.select_file.mouseReleaseEvent = self.addFile
        self.select_folder.mouseReleaseEvent = self.addFolder
        self.select_file_xml.mouseReleaseEvent = self.addXml
        self.select_hash.mouseReleaseEvent = self.hashFile
        self.hash.hide()
        self.code_hash.hide()
        # improt file/folder monitor
        self.select_file_monitor.mouseReleaseEvent = self.addFileMonitor
        self.select_folder_monitor.mouseReleaseEvent = self.addFolderMonitor

        # info hard disk
        self.disk_1.hide()
        self.disk_2.hide()
        self.disk_3.hide()
        self.disk_4.hide()

        # -----------------Functions of System------------------ #
        # def changeTabTo0(self, instance):
        #     # FaderWidget(self.main.currentWidget(),self.main.widget(0))
        #     self.main.setCurrentIndex(0)
        #
        # def changeTabTo1(self, instance):
        #     # FaderWidget(self.main.currentWidget(),self.main.widget(1))
        #     self.main.setCurrentIndex(1)
        #
        # def changeTabTo2(self, instance):
        #     self.main.setCurrentIndex(2)
        #
        # def changeTabTo3(self, instance):
        #     self.main.setCurrentIndex(3)
        #     self.clearDataInputInRule()
        #
        # def changeTabTo4(self, instance):
        #     self.main.setCurrentIndex(4)
        #
        # def changeTabTo5(self, instance):
        #     self.main.setCurrentIndex(5)
        #
        # def changeTabTo6(self, instance):
        #     self.main.setCurrentIndex(6)
        #
        # def changeTabTo7(self, instance):
        #     self.main.setCurrentIndex(7)
        #     self.clearDataInputOutRule()
        #
        # def changeTabTo8(self, instance):
        #     self.main.setCurrentIndex(8)
        #
        # def changeTabTo9(self, instance):
        #     self.main.setCurrentIndex(9)
        #
        # def changeTabTo10(self, instance):
        #     self.main.setCurrentIndex(10)
        #
        # def changeTabTo12(self, instance):
        #     self.main.setCurrentIndex(12)
        #
        # def changeTabTo13(self, instance):
        #     self.main.setCurrentIndex(13)
        #
        # def changeTabTo14(self, instance):
        #     self.main.setCurrentIndex(14)
        #
        # def changeTabTo15(self, instance):
        #     self.main.setCurrentIndex(15)
        #
        # def changeTabTo16(self, instance):
        #     self.main.setCurrentIndex(16)
        #     self.showDetailReportIntegrity()
        #
        # def changeTabTo17(self, instance):
        #     self.main.setCurrentIndex(17)
        #
        # def changeTabTo18(self, instance):
        #     self.main.setCurrentIndex(18)
        #
        # def changeTabTo19(self, instance):
        #     self.main.setCurrentIndex(19)
        #
        # def changeTabTo20(self, instance):
        #     self.main.setCurrentIndex(20)
        #     self.clearDataProgramRule()
        #
        # def changeTabTo21(self, instance):
        #     self.main.setCurrentIndex(21)
        #
        # def changeTabTo22(self, instance):
        #     self.main.setCurrentIndex(22)
        #
        # def changeTabTo23(self, instance):
        #     self.main.setCurrentIndex(23)
        #
        # def changeTabTo24(self, instance):
        #     self.main.setCurrentIndex(24)
        #
        # def changeTabTo25(self, instance):
        #     self.main.setCurrentIndex(25)
        #
        # def changeNetworkManagementTo_0(self, instance):
        #     self.mainSetting.setCurrentIndex(0)
        #
        # def changeNetworkManagementTo_1(self, instance):
        #     # FaderWidget(self.mainSetting.currentWidget(),self.mainSetting.widget(1))
        #     self.mainSetting.setCurrentIndex(1)
        #
        # def changeNetworkManagementTo_2(self, instance):
        #     self.mainSetting.setCurrentIndex(2)
        #
        # def changeNetworkManagementTo_3(self, instance):
        #     self.mainSetting.setCurrentIndex(3)
        #
        # def changeNetworkManagementTo_4(self, instance):
        #     self.mainSetting.setCurrentIndex(4)
        #
        # def changeNetworkManagementTo_5(self, instance):
        #     self.mainSetting.setCurrentIndex(5)
        #     # threadInfoNetwork = infoNetwork(MyApp())
        #     # threadInfoNetwork.start()

        # def setExecutionPolicy(self):
        #     p = subprocess.Popen(["powershell.exe", ".\powershell\setup.ps1"], stdout=subprocess.PIPE, shell=True)
        #     (output, err) = p.communicate()
        #     p_status = p.wait()

        # def ruleManagement(self):
        #     self.showIncomingTraffic()
        #     self.showOutTraffic()
        #     self.showProgramTraffic()
        #     self.hideColumnsRule()
        #
        # def runNetworkInfo(self):
        #     self.netinfo()
        #     self.getConigHardware()
        #     # self.getProcessList()
        #
        # def runManagement(self):
        #     self.dnsQueryList()
        #     self.dgaLog()

        # self.showBlackList()
        # self.showWhiteList()

        # def changeThisPCTo_0(self, instance):
        #     self.ThisPC.setCurrentIndex(0)
        #
        # def changeThisPCTo_1(self, instance):
        #     self.ThisPC.setCurrentIndex(1)
        #
        # def changeApplicationTo1(self, instance):
        #     self.application_stacked.setCurrentIndex(0)
        #
        # def changeApplicationTo2(self, instance):
        #     self.application_stacked.setCurrentIndex(1)
        #
        # def changeApplicationTo3(self, instance):
        #     self.application_stacked.setCurrentIndex(2)
        #
        # def changeMalwareTabTo0(self, instance):
        #     self.malwareStackedWidget.setCurrentIndex(0)
        #
        # def changeMalwareTabTo1(self, instance):
        #     self.malwareStackedWidget.setCurrentIndex(1)
        #
        # def changeMalwareTabTo2(self, instance):
        #     self.malwareStackedWidget.setCurrentIndex(2)
        #
        # def changeMalwareTabTo3(self, instance):
        #     self.malwareStackedWidget.setCurrentIndex(3)
        #
        # def changeReportToMain(self, instance):
        #     self.main.setCurrentIndex(10)
        #
        # def showReprotList(self, instance):
        #     self.main.setCurrentIndex(11)
        #
        # def runInfoApplication(self):
        #     # self.getProcessApp()
        #     self.showListApplications()
        #
        # def getInfoApp(self, instance):
        #     self.main.setCurrentIndex(9)

        def integrity(self_args):
            self_args.showPathTable()
            self_args.updatePathMonitor()

        @pyqtSlot()
        # -----------------File System------------------ #
        def scanFile(self_args, instance):
            option = QFileDialog.Options()
            fileName, _ = QFileDialog.getOpenFileName(self_args, 'Open file', '\\home', 'All files (*.*)',
                                                      options=QFileDialog.DontUseNativeDialog)

            if fileName:
                self_args.file_system_protection.setCurrentIndex(0)
                self_args.message_scan.setVisible(False)
                self_args.select_function.setText("Thực hiện mã hóa")
                self_args.file_info.setText(fileName)

        def changeState(self_args):
            if self_args.box_function.isChecked():
                self_args.select_function.setText("Thực hiện giải mã")
            else:
                self_args.select_function.setText("Thực hiện mã hóa")

        def startCrypt(self_args, path):
            path = path.replace("/", "\\")
            self_args.message_scan.setVisible(False)
            password = self_args.confirmPassword()
            if password == "canceled":
                self_args.start_crypt_folder.setEnabled(True)
                return
            else:
                if self_args.box_function.isChecked():
                    self_args.decryptFile(path, password, 0)
                else:
                    cmd = 'python script\\file_system\\crypto.py -e -f ' '"' + path + '"' + ' "' + password + '"'
                    self_args.encryptFile(cmd)

        def encryptFile(self_args, cmd):
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            state = str(output).find("Done encrypt file")
            # print(str(output), state)
            if state != -1:
                self_args.message_scan.setVisible(True)
                self_args.message_scan.setText("Mã hóa thành công")
                self_args.message_scan.setIcon(QtGui.QIcon("icon/check.png"))
                self_args.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");
            else:
                self_args.message_scan.setVisible(True)
                self_args.message_scan.setText("Mã hóa không thành công")
                self_args.message_scan.setIcon(QtGui.QIcon("icon/unnamed.png"))
                self_args.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");

        def decryptFile(self_args, path, password, Option):
            cmd = 'python script\\file_system\\crypto.py -d -f ' '"' + path + '"' + ' "' + password + '"' + ' ' + str(
                Option)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            state = str(output).find("Done decrypt file.")
            print(str(output), state)
            if state != -1:
                self_args.message_scan.setVisible(True)
                self_args.message_scan.setText("Giải mã thành công")
                self_args.message_scan.setIcon(QtGui.QIcon("icon/check.png"))
                self_args.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");
            elif str(output).find("Confirm override") != -1:
                status = self_args.confirmBox("Tệp tin giải mãi đã tồn tại, bạn có muốn ghi đè?")
                if status == 1:
                    self_args.decryptFile(path, password, 2)
            else:
                self_args.message_scan.setVisible(True)
                self_args.message_scan.setText("Giải mã không thành công")
                self_args.message_scan.setIcon(QtGui.QIcon("icon/unnamed.png"))
                self_args.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");

        def confirmPassword(self_args):
            dlg = QInputDialog()
            text, result = dlg.getText(self_args, "Nhập mật khẩu",
                                       "New password:", QLineEdit.Normal)

            if result and text:
                return text
            else:
                return "canceled"

        def confirmBox(mess):
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setText(mess)
            msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
            msg.setWindowFlags(QtCore.Qt.CustomizeWindowHint)
            ret = msg.exec_()
            if ret == QMessageBox.Ok:
                return 1
            else:
                return 0

        # -----------------Folder System------------------ #
        def scanFolder(self_args, instance):
            option = QFileDialog.Options()
            folderName = QFileDialog.getExistingDirectory(self_args, "Open Directory", "/home",
                                                          QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)

            if folderName:
                self_args.message_scan_2.setVisible(False)
                self_args.select_function_2.setText("Thực hiện mã hóa")
                self_args.folder_info.setText(folderName)

        def changeStateFolder(self_args):
            if self_args.box_function_2.isChecked():
                self_args.select_function_2.setText("Thực hiện giải mã")
            else:
                self_args.select_function_2.setText("Thực hiện mã hóa")

        def startCryptFolder(self_args, path):
            self_args.message_scan_2.setVisible(False)
            self_args.start_crypt_folder.setEnabled(False)
            password = self_args.confirmPassword()
            path = path.replace("/", "\\")
            if password == "canceled":
                self_args.start_crypt_folder.setEnabled(True)
                return
            else:
                cmd = ''
                global pathCrypt
                global eventCrypt
                global passwordCrypt
                if self_args.box_function_2.isChecked():
                    event = "decode"
                else:
                    event = "encode"
                pathCrypt = path
                eventCrypt = event
                passwordCrpyt = password
                self_args.path_crypt.setText("")
                self_args.progressBar_folder.setValue(0)
                self_args.progressBar_folder.setVisible(True)
                self_args.message_scan_2.setVisible(True)
                self_args.progressBar_folder.setMaximum(100)
                self_args.message_scan_2.setIcon(QtGui.QIcon())
                runThreadEncryptFolder = ThreadEncryptFolder(self_args)
                runThreadEncryptFolder.updatePath.connect(self_args.path_crypt.setText)
                runThreadEncryptFolder.updateProcessBar.connect(self_args.progressBar_folder.setValue)
                runThreadEncryptFolder.updateIndex.connect(self_args.message_scan_2.setText)
                runThreadEncryptFolder.completeCrypt.connect(self_args.completeCryptFolder)
                runThreadEncryptFolder.start()

        def completeCryptFolder(self_args):
            self_args.progressBar_folder.setValue(100)
            self_args.message_scan_2.setIcon(QtGui.QIcon("icon/check.png"))
            self_args.start_crypt_folder.setEnabled(True)

        # -----------------Integrity Check------------------ #
        def addFile(self_args, instance):
            fileName, _ = QFileDialog.getOpenFileName(self_args, 'Open file', '/home', 'All files (*.*)',
                                                      options=QFileDialog.DontUseNativeDialog)
            if fileName:
                self_args.path_file.setText(fileName)
                cmd = 'python script\\file_system\\demo_integrity.py -i ' + '"' + fileName + '"' + ' 0'
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                print(output, err, 12)
                p_status = p.wait()
                if p_status == 0:
                    self_args.showPathTable()

        def addFolder(self_args, instance):
            folderName = QFileDialog.getExistingDirectory(self_args, "Open Directory", "/home",
                                                          QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
            if folderName:
                self_args.path_folder.setText(folderName)
                cmd = 'python script\\file_system\\demo_integrity.py -i ' + '"' + folderName + '"' + ' 1'
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(str(output), err, "123")
                if p_status == 0:
                    self_args.showPathTable()

        def addXml(self_args, instance):
            fileName, _ = QFileDialog.getOpenFileName(self_args, 'Open file', '/home', '*.xml',
                                                      options=QFileDialog.DontUseNativeDialog)
            if fileName:
                self_args.path_xml.setText(fileName)
                cmd = 'python script\\file_system\\demo_integrity.py -x ' + '"' + fileName + '"'
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                if p_status == 0:
                    self_args.showPathTable()

        def hashFile(self_args, instance):
            self_args.alert_hash.hide()
            self_args.hash.hide()
            self_args.code_hash.hide()
            fileName, _ = QFileDialog.getOpenFileName(self_args, 'Open file', '/home', 'All files (*.*)',
                                                      options=QFileDialog.DontUseNativeDialog)
            if fileName:
                self_args.path_hash_file.setText(fileName)
                cmd = 'python script\\file_system\\demo_integrity.py -m ' + '"' + fileName + '"'
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                if p_status == 0:
                    state = json.loads(output.decode('ASCII'))['result']
                    data = json.loads(output.decode('ASCII'))['hash_str']
                    if state is True:
                        self_args.alert_hash.setVisible(True)
                        self_args.hash.setVisible(True)
                        self_args.code_hash.setVisible(True)
                        self_args.code_hash.setText(data)

                    else:
                        self_args.alert_hash.setIcon(QtGui.QIcon("icon/unnamed.png"))
                        self_args.alert_hash.setText("Không thành công")

        def showPathTable(self_args):
            cmd = 'python script\\file_system\\demo_integrity.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if p_status == 0:
                data = json.loads(output.decode('ASCII'))['check_list']
                self_args.path_list.setColumnCount(2)
                self_args.path_list.setRowCount(len(data))
                i = 0
                for data in data:
                    path = QPushButton()
                    path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
                    path.setStyleSheet("QPushButton {text-align: left;}");
                    path.setText(data[2])
                    self_args.path_list.setCellWidget(i, 0, path)
                    self_args.path_list.setItem(i, 1, QTableWidgetItem(str(data[1])))
                    i = i + 1
                self_args.path_list.setColumnHidden(1, True)

        def removePath(self_args):
            indexes = self_args.path_list.selectionModel().selectedRows()
            for index in sorted(indexes):
                path = self_args.path_list.cellWidget(index.row(), 0).text()
                Type = self_args.path_list.item(index.row(), 1).text()
                cmd = 'python script\\file_system\\demo_integrity.py -r ' + '"' + path + '"' + ' ' + Type
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
            self_args.showPathTable()

        def updatePath(self_args):
            self_args.showPathTable()

        def showDetailReportIntegrity(self_args):
            layout = QGridLayout()
            try:
                layout = self_args.scrollArea_intefrity.findChild(QLayout, "report_integrity_list")
                while layout.count():
                    child = layout.takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()
            except (Exception, ValueError):
                layout = QGridLayout(self_args.list_report_integrity)
                layout.setObjectName("report_integrity_list")
            cmd = 'python script\\file_system\\demo_integrity.py -a'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = json.loads(output.decode('ASCII'))['alert_list']

            i = 0
            for data in data:
                widget = QWidget()
                widget.setStyleSheet(
                    "QWidget {background: rgba(255,255,255,0.1); border-radius: 5px;} QLabel{background: transparent;} QWidget:hover {background: rgba(255,255,255,0.2);} QLabel:hover {background: transparent}")
                widget.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                widget.setObjectName(str(i) + "||widget_report")
                widget.setFixedHeight(65)
                name = QLabel(data[3])
                name.setObjectName(str(i) + "||label_name_report")
                status = QLabel(data[2])
                status.setObjectName(str(i) + "||label_status_report")
                status.setStyleSheet("QLabel {color: #72ac57}")
                timeReport = QLabel(data[1])
                timeReport.setObjectName(str(i) + "||label_time_report")
                timeReport.setAlignment(Qt.AlignCenter | Qt.AlignRight);

                layoutItem = QGridLayout(widget)
                layoutItem.addWidget(name, 0, 0)
                layoutItem.addWidget(timeReport, 0, 1)
                layoutItem.addWidget(status, 1, 0)
                layout.addWidget(widget, i, 0)
                i = i + 1
                if i == 100:
                    break

        def reportScan(self):
            cmd = 'python script\\file_system\\demo_integrity.py -a'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = json.loads(output.decode('ASCII'))['alert_list']
            i = 0
            for data in data:
                if i == 0:
                    self.path_integrity_1.setText(data[3])
                    self.status_integrity_1.setText(data[2])
                    self.status_integrity_1.setStyleSheet("QLabel {color: #72ac57}")
                    self.time_report_integrity_1.setText(data[1])
                elif i == 1:
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
                if i == 3:
                    break

        # -----------------Monitor File and Folder------------------ #
        def addFileMonitor(self, instance):
            fileName, _ = QFileDialog.getOpenFileName(self, 'Open file', '/home', 'All files (*.*)',
                                                      options=QFileDialog.DontUseNativeDialog)
            if fileName:addFileMonitor
                self.path_file_monitor.setText(fileName)
                cmd = 'python script\\file_system\\demo_monitor.py -i ' + '"' + fileName + '"' + ' 0'
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                print(output, err, "1234")
                p_status = p.wait()
                if p_status == 0:
                    self.showPathTableMonitor()

        def addFolderMonitor(self, instance):
            folderName = QFileDialog.getExistingDirectory(self, "Open Directory", "/home",
                                                          QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
            if folderName:
                self.path_folder.setText(folderName)
                cmd = 'python script\\file_system\\demo_monitor.py -i ' + '"' + folderName + '"' + ' 1'
                print(cmd, "abc")
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(str(output), err, "'12345")
                if p_status == 0:
                    self.showPathTableMonitor()

        def showPathTableMonitor(self):
            cmd = 'python script\\file_system\\demo_monitor.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = json.loads(output.decode('ASCII'))['check_list']
            if p_status == 0:
                self.path_list_monitor.setColumnCount(2)
                self.path_list_monitor.setRowCount(len(data))
                i = 0
                for data in data:
                    path = QPushButton()
                    path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
                    path.setStyleSheet("QPushButton {text-align: left;}")
                    path.setText(data[2])
                    self.path_list_monitor.setCellWidget(i, 0, path)
                    self.path_list_monitor.setItem(i, 1, QTableWidgetItem(str(data[1])))
                    i = i + 1
                self.path_list_monitor.setColumnHidden(1, True)

        def removePathMonitor(self):
            indexes = self.path_list_monitor.selectionModel().selectedRows()
            for index in sorted(indexes):
                path = self.path_list_monitor.cellWidget(index.row(), 0).text()
                Type = self.path_list_monitor.item(index.row(), 1).text()
                cmd = 'python script\\file_system\\demo_monitor.py -r ' + '"' + path + '"' + ' ' + Type
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
            self.showPathTableMonitor()

        def updatePathMonitor(self):
            self.showPathTableMonitor()
            self.reportScanMonitor()
            self.update_file_monitor.setText("Cập nhật")

        def reportScanMonitor(self):
            cmd = 'python script\\file_system\\demo_monitor.py -a'
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
                    if i == 100:
                        break
            except Exception as e:
                print(e)


class ThreadEncryptFolder (QThread):
    updatePath = pyqtSignal(str)
    updateProcessBar = pyqtSignal(int)
    updateIndex = pyqtSignal(str)
    completeCrypt = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        global eventCrypt
        global passwordCrypt
        global pathCrypt
        self.path=pathCrypt
        self.password = passwordCrypt
        self.event = eventCrypt

    def run(self):
        self.name = "thread_Encrypt_folder"

        count = 0
        for r, d, f in os.walk(self.path):
            for file in f:
                count=count+1

        totalFile = count
        i = 0
        succ = 0

        if self.event == "encode":
            for r, d, f in os.walk(self.path):
                for file in f:
                    filePath = os.path.join(r, file)
                    self.updatePath.emit("Tệp tin: "+filePath)
                    try:
                        cmd = 'python script\\file_system\\crypto.py -e -f ' '"'+filePath+'"' + ' "'+self.password+'"'
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
                            print(f + " file encryption failed")

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
                        cmd = 'python script\\file_system\\crypto.py -d -f ' '"'+filePath+'"' + ' "'+self.password+'"'+' 2'
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
                            print(f + " file decryption failed")

                    except Exception as e:
                        self.updateProcessBar.emit(int(i*(100/totalFile)))
                        self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                        print(e)
                        i = i + 1
            self.completeCrypt.emit()


class ThreadScanIntegrity(QThread):
    updateReportScan = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        while True:
            # lay danh sach tep tin/thu muc kiem tra tinh toan ven
            cmd = 'python script\\file_system\\demo_integrity.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            # Vong lap quet tung tep tin/ thu muc
            if p_status == 0:
                data = json.loads(output.decode('ASCII'))['check_list']
                for d in data:
                    cmd = 'python script\\file_system\\demo_integrity.py -s ' + '"' + d[2] + '"' + " " + str(d[1])
                    print(cmd)
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()
                    print(output)
            self.updateReportScan.emit()
            time.sleep(60)


class ThreadScanMonitor(threading.Thread):
    def __init__(self, window):
        threading.Thread.__init__(self)
        self.window = window

    def run(self):
        while True:
            # Tim id bao cao moi nhat
            cmdGetId = 'python script\\file_system\\demo_monitor.py -e'
            pID = subprocess.Popen(cmdGetId, stdout=subprocess.PIPE, shell=True)
            (outputId, err) = pID.communicate()
            pID_status = pID.wait()
            ID = json.loads(outputId.decode('ASCII'))['last_alert_id']

            # lay danh sach tep tin/thu muc theo doi
            cmd = 'python script\\file_system\\demo_monitor.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            # Vong lap quet tung tep tin/ thu muc
            if p_status == 0:
                data = json.loads(output.decode('ASCII'))['moniter_list']
                for d in data:
                    cmd = 'python script\\file_system\\demo_monitor.py -s ' + '"' + d[2] + '"' + " " + str(d[1])
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()

            # lay danh sach bao cao phat hien thay doi vua quet
            # cmd = 'python script\\file_system\\demo_monitor.py -a '+str(ID)
            # p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            # (output, err) = p.communicate()
            # p_status = p.wait()
            # alert = json.loads(output.decode('ASCII'))['alert_list']
            # if(len(alert)>0):
            #     alertSend = json.loads(output.decode('ASCII'))
            #     ThreadsendReportMonitorToServer = sendReportMonitorToServer(alertSend)
            #     ThreadsendReportMonitorToServer.start()

            time.sleep(3600)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont()
    font.setPixelSize(13)
    font.setFamily(font.defaultFamily())
    app.setFont(font)
    window = LoadingApp()
    window.show()

    sys.exit(app.exec_())
