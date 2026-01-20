# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IMessageEditorController
from array import array
from javax.swing import (
    JPanel, JScrollPane, JButton, BorderFactory, JOptionPane, 
    JSplitPane, JList, DefaultListModel, JTable, SwingUtilities, 
    JTabbedPane, JPopupMenu, JMenuItem, JCheckBox, ListCellRenderer
)
from java.awt import BorderLayout, Component
from java.util import ArrayList
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseAdapter

class KeywordItem:
    def __init__(self, text, active=True):
        self.text = text
        self.active = active
    def __str__(self):
        return self.text

class CheckboxListRenderer(JCheckBox, ListCellRenderer):
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        self.setText(str(value))
        self.setSelected(value.active)
        self.setBackground(list.getSelectionBackground() if isSelected else list.getBackground())
        self.setForeground(list.getSelectionForeground() if isSelected else list.getForeground())
        self.setEnabled(list.isEnabled())
        self.setFont(list.getFont())
        return self

class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        default_keywords = [
            '"success": false', '"authenticated": false', '"isValid": 0',
            '"status": "fail"', '"status": "false"', '"active": false','"active": "false"',
            '"role": "user"', '"role": "default"', '"role": "standart"',
            '"isAdmin": false', '"isAdmin": "false"', '"privileges":', '"user_type":', '"otp_verified": false', '"IsCompleted":false', '"IsSucceeded":false', "otp":"false"
        ]
        
        self._keyword_objects = [KeywordItem(kw) for kw in default_keywords]
        self._issue_count = 0
        self._global_id_counter = 0 
        self._issues_detailed = [] 
        self._current_message_info = None
        
        self._callbacks.setExtensionName("Responser")
        self.createUI()
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        print("[+] Responser Added")
        
    def createUI(self):
        self._jPanel = JPanel(BorderLayout())
        self._jPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        mainSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._jPanel.add(mainSplitPane, BorderLayout.CENTER)
        
        verticalSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        mainSplitPane.setRightComponent(verticalSplitPane)

        leftPanel = JPanel(BorderLayout())
        leftPanel.setBorder(BorderFactory.createTitledBorder("Keywords (Enable/Disable)"))
        self.keywordListModel = DefaultListModel()
        for item in self._keyword_objects:
            self.keywordListModel.addElement(item)
            
        self.keywordJList = JList(self.keywordListModel)
        self.keywordJList.setCellRenderer(CheckboxListRenderer())
        self.keywordJList.addMouseListener(KeywordToggleListener(self))
        
        leftPanel.add(JScrollPane(self.keywordJList), BorderLayout.CENTER)
        
        buttonPanel = JPanel()
        self.addButton = JButton("Add")
        self.addButton.addActionListener(self.addKeyword)
        self.removeButton = JButton("Remove")
        self.removeButton.addActionListener(self.removeKeyword)
        buttonPanel.add(self.addButton)
        buttonPanel.add(self.removeButton)
        leftPanel.add(buttonPanel, BorderLayout.SOUTH)
        
        mainSplitPane.setLeftComponent(leftPanel)
        mainSplitPane.setResizeWeight(0.2)

        issueListPanel = JPanel(BorderLayout())
        issueListPanel.setBorder(BorderFactory.createTitledBorder("Detected Findings"))
        columns = ["ID", "Status", "Method", "Keyword", "Path", "Length", "Source Tool"]
        
        self.tableModel = ReadOnlyTableModel(columns, 0)
        self.issueTable = JTable(self.tableModel)
        self.issueTable.setAutoCreateRowSorter(True)
        
        issueListPanel.add(JScrollPane(self.issueTable), BorderLayout.CENTER)
        verticalSplitPane.setTopComponent(issueListPanel)

        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        
        reqPanel = JPanel(BorderLayout())
        reqPanel.setBorder(BorderFactory.createTitledBorder("Request"))
        reqPanel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        
        resPanel = JPanel(BorderLayout())
        resPanel.setBorder(BorderFactory.createTitledBorder("Response"))
        resPanel.add(self._responseViewer.getComponent(), BorderLayout.CENTER)
        
        detailSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, resPanel)
        detailSplit.setResizeWeight(0.5)
        verticalSplitPane.setBottomComponent(detailSplit)
        verticalSplitPane.setResizeWeight(0.4)
        
        self.issueTable.addMouseListener(IssueTableMouseListener(self))

    def getHttpService(self): return self._current_message_info.getHttpService() if self._current_message_info else None
    def getRequest(self): return self._current_message_info.getRequest() if self._current_message_info else None
    def getResponse(self): return self._current_message_info.getResponse() if self._current_message_info else None
    def getTabCaption(self): return "Responser ({})".format(self._issue_count) if self._issue_count > 0 else "Responser"
    def getUiComponent(self): return self._jPanel
    
    def updateTabTitle(self):
        def update():
            try:
                comp = self.getUiComponent()
                parent = comp.getParent()
                if isinstance(parent, JTabbedPane):
                    idx = parent.indexOfComponent(comp)
                    if idx != -1: parent.setTitleAt(idx, self.getTabCaption())
            except: pass
        SwingUtilities.invokeLater(update)

    def addKeyword(self, event):
        kw = JOptionPane.showInputDialog(self._jPanel, "Enter Keyword:")
        if kw and kw.strip():
            new_item = KeywordItem(kw.strip())
            self._keyword_objects.append(new_item)
            self.keywordListModel.addElement(new_item)

    def removeKeyword(self, event):
        idx = self.keywordJList.getSelectedIndex()
        if idx != -1:
            item = self.keywordListModel.getElementAt(idx)
            self._keyword_objects.remove(item)
            self.keywordListModel.remove(idx)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not messageInfo.getResponse(): return
        active_keywords = [k.text for k in self._keyword_objects if k.active]
        if not active_keywords: return
        response = messageInfo.getResponse()
        analyzedRes = self._helpers.analyzeResponse(response)
        body = response[analyzedRes.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(body).lower()
        found_kws = [kw for kw in active_keywords if kw.lower() in bodyStr]
        if found_kws:
            reqInfo = self._helpers.analyzeRequest(messageInfo)
            method, path = reqInfo.getMethod(), reqInfo.getUrl().getPath()
            status, length = str(analyzedRes.getStatusCode()), str(len(response))
            tool = self._callbacks.getToolName(toolFlag)
            for kw in found_kws:
                SwingUtilities.invokeLater(lambda: self.addRow(messageInfo, status, method, kw, path, length, tool))

    def addRow(self, msg, status, method, kw, path, length, tool):
        self._issue_count += 1
        self._global_id_counter += 1
        self.tableModel.addRow([self._global_id_counter, status, method, kw, path, length, tool])
        self._issues_detailed.append({'msg': msg})
        self.updateTabTitle()

class KeywordToggleListener(MouseAdapter):
    def __init__(self, ext):
        self.ext = ext
    def mousePressed(self, e):
        idx = self.ext.keywordJList.locationToIndex(e.getPoint())
        if idx != -1:
            rect = self.ext.keywordJList.getCellBounds(idx, idx)
            if rect is not None and rect.contains(e.getPoint()):
                item = self.ext.keywordListModel.getElementAt(idx)
                item.active = not item.active
                self.ext.keywordJList.repaint()

class IssueTableMouseListener(MouseAdapter):
    def __init__(self, ext):
        self.ext = ext
        self.menu = JPopupMenu()
        item = JMenuItem("Delete Entry")
        item.addActionListener(self.delete)
        self.menu.add(item)
    def mouseClicked(self, e):
        if SwingUtilities.isRightMouseButton(e):
            row = self.ext.issueTable.rowAtPoint(e.getPoint())
            if row != -1:
                self.ext.issueTable.setRowSelectionInterval(row, row)
                self.menu.show(e.getComponent(), e.getX(), e.getY())
        else:
            vRow = self.ext.issueTable.getSelectedRow()
            if vRow != -1:
                mRow = self.ext.issueTable.convertRowIndexToModel(vRow)
                data = self.ext._issues_detailed[mRow]
                self.ext._current_message_info = data['msg']
                self.ext._requestViewer.setMessage(data['msg'].getRequest(), False)
                self.ext._responseViewer.setMessage(data['msg'].getResponse(), False)
    def delete(self, e):
        vRow = self.ext.issueTable.getSelectedRow()
        if vRow != -1:
            mRow = self.ext.issueTable.convertRowIndexToModel(vRow)
            self.ext.tableModel.removeRow(mRow)
            del self.ext._issues_detailed[mRow]
            self.ext._issue_count -= 1
            self.ext.updateTabTitle()

class CustomScanIssue(IScanIssue):
    def __init__(self, svc, url, msg, name, det, sev, conf):
        self._svc, self._url, self._msg, self._name, self._det, self._sev, self._conf = svc, url, msg, name, det, sev, conf
    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._sev
    def getConfidence(self): return self._conf
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._det
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._msg
    def getHttpService(self): return self._svc
