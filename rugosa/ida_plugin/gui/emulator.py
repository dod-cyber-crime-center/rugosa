# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'emulator.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_EmulatorForm(object):
    def setupUi(self, EmulatorForm):
        EmulatorForm.setObjectName("EmulatorForm")
        EmulatorForm.resize(770, 796)
        self.verticalLayout = QtWidgets.QVBoxLayout(EmulatorForm)
        self.verticalLayout.setObjectName("verticalLayout")
        self.emulator_controls = QtWidgets.QHBoxLayout()
        self.emulator_controls.setObjectName("emulator_controls")
        self.trace_depth_label = QtWidgets.QLabel(EmulatorForm)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.trace_depth_label.sizePolicy().hasHeightForWidth())
        self.trace_depth_label.setSizePolicy(sizePolicy)
        self.trace_depth_label.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.trace_depth_label.setObjectName("trace_depth_label")
        self.emulator_controls.addWidget(self.trace_depth_label)
        self.trace_depth = QtWidgets.QSpinBox(EmulatorForm)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.trace_depth.sizePolicy().hasHeightForWidth())
        self.trace_depth.setSizePolicy(sizePolicy)
        self.trace_depth.setObjectName("trace_depth")
        self.emulator_controls.addWidget(self.trace_depth)
        self.call_depth_label = QtWidgets.QLabel(EmulatorForm)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.call_depth_label.sizePolicy().hasHeightForWidth())
        self.call_depth_label.setSizePolicy(sizePolicy)
        self.call_depth_label.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.call_depth_label.setObjectName("call_depth_label")
        self.emulator_controls.addWidget(self.call_depth_label)
        self.call_depth = QtWidgets.QSpinBox(EmulatorForm)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.call_depth.sizePolicy().hasHeightForWidth())
        self.call_depth.setSizePolicy(sizePolicy)
        self.call_depth.setObjectName("call_depth")
        self.emulator_controls.addWidget(self.call_depth)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.emulator_controls.addItem(spacerItem)
        self.exhaustive = QtWidgets.QCheckBox(EmulatorForm)
        self.exhaustive.setChecked(True)
        self.exhaustive.setObjectName("exhaustive")
        self.emulator_controls.addWidget(self.exhaustive)
        self.follow_loops = QtWidgets.QCheckBox(EmulatorForm)
        self.follow_loops.setObjectName("follow_loops")
        self.emulator_controls.addWidget(self.follow_loops)
        self.verticalLayout.addLayout(self.emulator_controls)
        self.emulator_buttons = QtWidgets.QHBoxLayout()
        self.emulator_buttons.setObjectName("emulator_buttons")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.emulator_buttons.addItem(spacerItem1)
        self.run_button = QtWidgets.QPushButton(EmulatorForm)
        self.run_button.setObjectName("run_button")
        self.emulator_buttons.addWidget(self.run_button)
        self.step_over_button = QtWidgets.QPushButton(EmulatorForm)
        self.step_over_button.setEnabled(False)
        self.step_over_button.setObjectName("step_over_button")
        self.emulator_buttons.addWidget(self.step_over_button)
        self.step_into_button = QtWidgets.QPushButton(EmulatorForm)
        self.step_into_button.setEnabled(False)
        self.step_into_button.setObjectName("step_into_button")
        self.emulator_buttons.addWidget(self.step_into_button)
        self.step_out_button = QtWidgets.QPushButton(EmulatorForm)
        self.step_out_button.setEnabled(False)
        self.step_out_button.setObjectName("step_out_button")
        self.emulator_buttons.addWidget(self.step_out_button)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.emulator_buttons.addItem(spacerItem2)
        self.verticalLayout.addLayout(self.emulator_buttons)
        self.instruction = QtWidgets.QLabel(EmulatorForm)
        self.instruction.setObjectName("instruction")
        self.verticalLayout.addWidget(self.instruction)
        self.tabs = QtWidgets.QTabWidget(EmulatorForm)
        self.tabs.setTabPosition(QtWidgets.QTabWidget.North)
        self.tabs.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(False)
        self.tabs.setMovable(True)
        self.tabs.setObjectName("tabs")
        self.operands_tab = QtWidgets.QWidget()
        self.operands_tab.setObjectName("operands_tab")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.operands_tab)
        self.verticalLayout_2.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.operands_table = QtWidgets.QTableWidget(self.operands_tab)
        self.operands_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.operands_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.operands_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.operands_table.setObjectName("operands_table")
        self.operands_table.setColumnCount(6)
        self.operands_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.operands_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.operands_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.operands_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.operands_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.operands_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.operands_table.setHorizontalHeaderItem(5, item)
        self.operands_table.horizontalHeader().setCascadingSectionResizes(True)
        self.operands_table.verticalHeader().setVisible(False)
        self.verticalLayout_2.addWidget(self.operands_table)
        self.tabs.addTab(self.operands_tab, "")
        self.registers_tab = QtWidgets.QWidget()
        self.registers_tab.setObjectName("registers_tab")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.registers_tab)
        self.verticalLayout_3.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.registers_table = QtWidgets.QTableWidget(self.registers_tab)
        self.registers_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.registers_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.registers_table.setObjectName("registers_table")
        self.registers_table.setColumnCount(3)
        self.registers_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.registers_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.registers_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.registers_table.setHorizontalHeaderItem(2, item)
        self.registers_table.verticalHeader().setVisible(False)
        self.verticalLayout_3.addWidget(self.registers_table)
        self.tabs.addTab(self.registers_tab, "")
        self.memory_tab = QtWidgets.QWidget()
        self.memory_tab.setObjectName("memory_tab")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.memory_tab)
        self.verticalLayout_6.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.memory_controls = QtWidgets.QHBoxLayout()
        self.memory_controls.setContentsMargins(-1, 3, -1, 0)
        self.memory_controls.setObjectName("memory_controls")
        self.label = QtWidgets.QLabel(self.memory_tab)
        self.label.setObjectName("label")
        self.memory_controls.addWidget(self.label)
        self.memory_start = QtWidgets.QLineEdit(self.memory_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.memory_start.sizePolicy().hasHeightForWidth())
        self.memory_start.setSizePolicy(sizePolicy)
        self.memory_start.setObjectName("memory_start")
        self.memory_controls.addWidget(self.memory_start)
        self.label_2 = QtWidgets.QLabel(self.memory_tab)
        self.label_2.setObjectName("label_2")
        self.memory_controls.addWidget(self.label_2)
        self.memory_size = QtWidgets.QSpinBox(self.memory_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.memory_size.sizePolicy().hasHeightForWidth())
        self.memory_size.setSizePolicy(sizePolicy)
        self.memory_size.setMinimumSize(QtCore.QSize(10, 0))
        self.memory_size.setMaximum(65535)
        self.memory_size.setProperty("value", 1024)
        self.memory_size.setObjectName("memory_size")
        self.memory_controls.addWidget(self.memory_size)
        self.memory_load_button = QtWidgets.QPushButton(self.memory_tab)
        self.memory_load_button.setObjectName("memory_load_button")
        self.memory_controls.addWidget(self.memory_load_button)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.memory_controls.addItem(spacerItem3)
        self.memory_export_button = QtWidgets.QPushButton(self.memory_tab)
        self.memory_export_button.setObjectName("memory_export_button")
        self.memory_controls.addWidget(self.memory_export_button)
        self.verticalLayout_6.addLayout(self.memory_controls)
        self.memory_hexdump = QtWidgets.QTextEdit(self.memory_tab)
        self.memory_hexdump.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.memory_hexdump.setReadOnly(True)
        self.memory_hexdump.setAcceptRichText(False)
        self.memory_hexdump.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.memory_hexdump.setObjectName("memory_hexdump")
        self.verticalLayout_6.addWidget(self.memory_hexdump)
        self.memory_blocks_table = QtWidgets.QTableWidget(self.memory_tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.memory_blocks_table.sizePolicy().hasHeightForWidth())
        self.memory_blocks_table.setSizePolicy(sizePolicy)
        self.memory_blocks_table.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.memory_blocks_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.memory_blocks_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.memory_blocks_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.memory_blocks_table.setObjectName("memory_blocks_table")
        self.memory_blocks_table.setColumnCount(3)
        self.memory_blocks_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.memory_blocks_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.memory_blocks_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.memory_blocks_table.setHorizontalHeaderItem(2, item)
        self.memory_blocks_table.verticalHeader().setVisible(False)
        self.verticalLayout_6.addWidget(self.memory_blocks_table)
        self.tabs.addTab(self.memory_tab, "")
        self.variables_tab = QtWidgets.QWidget()
        self.variables_tab.setObjectName("variables_tab")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.variables_tab)
        self.verticalLayout_4.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.variables_table = QtWidgets.QTableWidget(self.variables_tab)
        self.variables_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.variables_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.variables_table.setObjectName("variables_table")
        self.variables_table.setColumnCount(6)
        self.variables_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.variables_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.variables_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.variables_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.variables_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.variables_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.variables_table.setHorizontalHeaderItem(5, item)
        self.variables_table.horizontalHeader().setCascadingSectionResizes(True)
        self.variables_table.horizontalHeader().setSortIndicatorShown(True)
        self.variables_table.verticalHeader().setVisible(False)
        self.variables_table.verticalHeader().setCascadingSectionResizes(False)
        self.verticalLayout_4.addWidget(self.variables_table)
        self.tabs.addTab(self.variables_tab, "")
        self.function_arguments_tab = QtWidgets.QWidget()
        self.function_arguments_tab.setObjectName("function_arguments_tab")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.function_arguments_tab)
        self.verticalLayout_5.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_5.setSpacing(6)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.function_arguments_form = QtWidgets.QHBoxLayout()
        self.function_arguments_form.setContentsMargins(3, 3, 3, 3)
        self.function_arguments_form.setObjectName("function_arguments_form")
        self.function_signature = QtWidgets.QLabel(self.function_arguments_tab)
        self.function_signature.setObjectName("function_signature")
        self.function_arguments_form.addWidget(self.function_signature)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.function_arguments_form.addItem(spacerItem4)
        self.num_args_label = QtWidgets.QLabel(self.function_arguments_tab)
        self.num_args_label.setObjectName("num_args_label")
        self.function_arguments_form.addWidget(self.num_args_label)
        self.num_args = QtWidgets.QSpinBox(self.function_arguments_tab)
        self.num_args.setObjectName("num_args")
        self.function_arguments_form.addWidget(self.num_args)
        self.verticalLayout_5.addLayout(self.function_arguments_form)
        self.function_arguments_table = QtWidgets.QTableWidget(self.function_arguments_tab)
        self.function_arguments_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.function_arguments_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.function_arguments_table.setObjectName("function_arguments_table")
        self.function_arguments_table.setColumnCount(8)
        self.function_arguments_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(6, item)
        item = QtWidgets.QTableWidgetItem()
        self.function_arguments_table.setHorizontalHeaderItem(7, item)
        self.function_arguments_table.verticalHeader().setVisible(False)
        self.verticalLayout_5.addWidget(self.function_arguments_table)
        self.tabs.addTab(self.function_arguments_tab, "")
        self.call_history_tab = QtWidgets.QWidget()
        self.call_history_tab.setObjectName("call_history_tab")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.call_history_tab)
        self.verticalLayout_8.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.call_history_table = QtWidgets.QTableWidget(self.call_history_tab)
        self.call_history_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.call_history_table.setObjectName("call_history_table")
        self.call_history_table.setColumnCount(2)
        self.call_history_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.call_history_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.call_history_table.setHorizontalHeaderItem(1, item)
        self.call_history_table.verticalHeader().setVisible(False)
        self.verticalLayout_8.addWidget(self.call_history_table)
        self.tabs.addTab(self.call_history_tab, "")
        self.actions_tab = QtWidgets.QWidget()
        self.actions_tab.setObjectName("actions_tab")
        self.actions_layout = QtWidgets.QVBoxLayout(self.actions_tab)
        self.actions_layout.setContentsMargins(0, 6, 0, 0)
        self.actions_layout.setObjectName("actions_layout")
        self.actions_table = QtWidgets.QTreeWidget(self.actions_tab)
        self.actions_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.actions_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.actions_table.setIndentation(20)
        self.actions_table.setRootIsDecorated(True)
        self.actions_table.setUniformRowHeights(False)
        self.actions_table.setAnimated(True)
        self.actions_table.setHeaderHidden(False)
        self.actions_table.setObjectName("actions_table")
        self.actions_table.header().setSortIndicatorShown(True)
        self.actions_layout.addWidget(self.actions_table)
        self.tabs.addTab(self.actions_tab, "")
        self.stdout_tab = QtWidgets.QWidget()
        self.stdout_tab.setObjectName("stdout_tab")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.stdout_tab)
        self.verticalLayout_7.setContentsMargins(0, 6, 0, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem5)
        self.stdout_export_button = QtWidgets.QPushButton(self.stdout_tab)
        self.stdout_export_button.setObjectName("stdout_export_button")
        self.horizontalLayout.addWidget(self.stdout_export_button)
        self.verticalLayout_7.addLayout(self.horizontalLayout)
        self.stdout_textdump = QtWidgets.QTextEdit(self.stdout_tab)
        self.stdout_textdump.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.stdout_textdump.setReadOnly(True)
        self.stdout_textdump.setAcceptRichText(False)
        self.stdout_textdump.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.stdout_textdump.setObjectName("stdout_textdump")
        self.verticalLayout_7.addWidget(self.stdout_textdump)
        self.tabs.addTab(self.stdout_tab, "")
        self.verticalLayout.addWidget(self.tabs)
        self.status = QtWidgets.QLabel(EmulatorForm)
        self.status.setObjectName("status")
        self.verticalLayout.addWidget(self.status)

        self.retranslateUi(EmulatorForm)
        self.tabs.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(EmulatorForm)

    def retranslateUi(self, EmulatorForm):
        _translate = QtCore.QCoreApplication.translate
        EmulatorForm.setWindowTitle(_translate("EmulatorForm", "Rugosa Emulator"))
        self.trace_depth_label.setToolTip(_translate("EmulatorForm", "Number of levels of parent callers to emulate"))
        self.trace_depth_label.setText(_translate("EmulatorForm", "Trace Depth"))
        self.call_depth_label.setToolTip(_translate("EmulatorForm", "Number of call levels deep to emulate"))
        self.call_depth_label.setText(_translate("EmulatorForm", "Call Depth"))
        self.exhaustive.setToolTip(_translate("EmulatorForm", "Whether to also follow loops for parent callers"))
        self.exhaustive.setText(_translate("EmulatorForm", "Exhaustive"))
        self.follow_loops.setToolTip(_translate("EmulatorForm", "Whether to emulate loops instead of forcing a downward path"))
        self.follow_loops.setText(_translate("EmulatorForm", "Follow Loops"))
        self.run_button.setToolTip(_translate("EmulatorForm", "Emulate up to the current highlighted instruction"))
        self.run_button.setText(_translate("EmulatorForm", "Run"))
        self.step_over_button.setToolTip(_translate("EmulatorForm", "Emulate the next instruction"))
        self.step_over_button.setText(_translate("EmulatorForm", "Step Over"))
        self.step_into_button.setToolTip(_translate("EmulatorForm", "Not Supported Yet"))
        self.step_into_button.setText(_translate("EmulatorForm", "Step Into"))
        self.step_out_button.setToolTip(_translate("EmulatorForm", "Not Supported Yet"))
        self.step_out_button.setText(_translate("EmulatorForm", "Step Out"))
        self.instruction.setToolTip(_translate("EmulatorForm", "<html><head/><body><p>Current instruction emulated up to.</p></body></html>"))
        self.instruction.setText(_translate("EmulatorForm", "<instruction>"))
        self.operands_tab.setToolTip(_translate("EmulatorForm", "Contents of the operands of the current instruction"))
        self.operands_table.setSortingEnabled(True)
        item = self.operands_table.horizontalHeaderItem(0)
        item.setText(_translate("EmulatorForm", "Index"))
        item = self.operands_table.horizontalHeaderItem(1)
        item.setText(_translate("EmulatorForm", "Size"))
        item = self.operands_table.horizontalHeaderItem(2)
        item.setText(_translate("EmulatorForm", "Text"))
        item = self.operands_table.horizontalHeaderItem(3)
        item.setText(_translate("EmulatorForm", "Address"))
        item = self.operands_table.horizontalHeaderItem(4)
        item.setText(_translate("EmulatorForm", "Value"))
        item = self.operands_table.horizontalHeaderItem(5)
        item.setText(_translate("EmulatorForm", "Referenced Data"))
        self.tabs.setTabText(self.tabs.indexOf(self.operands_tab), _translate("EmulatorForm", "Operands"))
        self.registers_tab.setToolTip(_translate("EmulatorForm", "Content of the registers"))
        self.registers_table.setSortingEnabled(True)
        item = self.registers_table.horizontalHeaderItem(0)
        item.setText(_translate("EmulatorForm", "Name"))
        item = self.registers_table.horizontalHeaderItem(1)
        item.setText(_translate("EmulatorForm", "Value"))
        item = self.registers_table.horizontalHeaderItem(2)
        item.setText(_translate("EmulatorForm", "Referenced Data"))
        self.tabs.setTabText(self.tabs.indexOf(self.registers_tab), _translate("EmulatorForm", "Registers"))
        self.memory_tab.setToolTip(_translate("EmulatorForm", "Contents of memory"))
        self.label.setText(_translate("EmulatorForm", "Start Address"))
        self.memory_start.setPlaceholderText(_translate("EmulatorForm", "0x401000"))
        self.label_2.setText(_translate("EmulatorForm", "Size"))
        self.memory_load_button.setText(_translate("EmulatorForm", "Load"))
        self.memory_export_button.setText(_translate("EmulatorForm", "Export"))
        self.memory_blocks_table.setToolTip(_translate("EmulatorForm", "Currently mapped memory blocks"))
        item = self.memory_blocks_table.horizontalHeaderItem(0)
        item.setText(_translate("EmulatorForm", "Start"))
        item = self.memory_blocks_table.horizontalHeaderItem(1)
        item.setText(_translate("EmulatorForm", "End"))
        item = self.memory_blocks_table.horizontalHeaderItem(2)
        item.setText(_translate("EmulatorForm", "Size"))
        self.tabs.setTabText(self.tabs.indexOf(self.memory_tab), _translate("EmulatorForm", "Memory"))
        self.variables_tab.setToolTip(_translate("EmulatorForm", "Contents of labeled data"))
        self.variables_table.setSortingEnabled(True)
        item = self.variables_table.horizontalHeaderItem(0)
        item.setText(_translate("EmulatorForm", "Address"))
        item = self.variables_table.horizontalHeaderItem(1)
        item.setText(_translate("EmulatorForm", "Stack Offset"))
        item = self.variables_table.horizontalHeaderItem(2)
        item.setText(_translate("EmulatorForm", "Data Type"))
        item = self.variables_table.horizontalHeaderItem(3)
        item.setText(_translate("EmulatorForm", "Size"))
        item = self.variables_table.horizontalHeaderItem(4)
        item.setText(_translate("EmulatorForm", "Name"))
        item = self.variables_table.horizontalHeaderItem(5)
        item.setText(_translate("EmulatorForm", "Value"))
        self.tabs.setTabText(self.tabs.indexOf(self.variables_tab), _translate("EmulatorForm", "Variables"))
        self.function_arguments_tab.setToolTip(_translate("EmulatorForm", "Contents of arguments if current instruction is a function call"))
        self.function_signature.setToolTip(_translate("EmulatorForm", "Function signature of called function"))
        self.function_signature.setText(_translate("EmulatorForm", "<function signature>"))
        self.num_args_label.setToolTip(_translate("EmulatorForm", "Adjust the number of arguments for the function call"))
        self.num_args_label.setText(_translate("EmulatorForm", "Number of Arguments"))
        self.function_arguments_table.setSortingEnabled(True)
        item = self.function_arguments_table.horizontalHeaderItem(0)
        item.setText(_translate("EmulatorForm", "Ordinal"))
        item = self.function_arguments_table.horizontalHeaderItem(1)
        item.setText(_translate("EmulatorForm", "Location"))
        item = self.function_arguments_table.horizontalHeaderItem(2)
        item.setText(_translate("EmulatorForm", "Data Type"))
        item = self.function_arguments_table.horizontalHeaderItem(3)
        item.setText(_translate("EmulatorForm", "Size"))
        item = self.function_arguments_table.horizontalHeaderItem(4)
        item.setText(_translate("EmulatorForm", "Name"))
        item = self.function_arguments_table.horizontalHeaderItem(5)
        item.setText(_translate("EmulatorForm", "Address"))
        item = self.function_arguments_table.horizontalHeaderItem(6)
        item.setText(_translate("EmulatorForm", "Value"))
        item = self.function_arguments_table.horizontalHeaderItem(7)
        item.setText(_translate("EmulatorForm", "Referenced Data"))
        self.tabs.setTabText(self.tabs.indexOf(self.function_arguments_tab), _translate("EmulatorForm", "Function Arguments"))
        self.call_history_tab.setToolTip(_translate("EmulatorForm", "Function calls observed during emulation"))
        self.call_history_table.setSortingEnabled(True)
        item = self.call_history_table.horizontalHeaderItem(0)
        item.setText(_translate("EmulatorForm", "Address"))
        item = self.call_history_table.horizontalHeaderItem(1)
        item.setText(_translate("EmulatorForm", "Function Call"))
        self.tabs.setTabText(self.tabs.indexOf(self.call_history_tab), _translate("EmulatorForm", "Call History"))
        self.actions_tab.setToolTip(_translate("EmulatorForm", "Interesting actions observed during emulation"))
        self.actions_table.setSortingEnabled(True)
        self.actions_table.headerItem().setText(0, _translate("EmulatorForm", "Address"))
        self.actions_table.headerItem().setText(1, _translate("EmulatorForm", "Action"))
        self.actions_table.headerItem().setText(2, _translate("EmulatorForm", "Attribute"))
        self.actions_table.headerItem().setText(3, _translate("EmulatorForm", "Value"))
        self.tabs.setTabText(self.tabs.indexOf(self.actions_tab), _translate("EmulatorForm", "Actions"))
        self.stdout_tab.setToolTip(_translate("EmulatorForm", "Current contents of the stdout stream"))
        self.stdout_export_button.setText(_translate("EmulatorForm", "Export"))
        self.tabs.setTabText(self.tabs.indexOf(self.stdout_tab), _translate("EmulatorForm", "Stdout"))
        self.status.setText(_translate("EmulatorForm", "<status>"))
