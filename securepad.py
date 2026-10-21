#!/usr/bin/env python3
"""SecurePad Studio 3.0: VS Code-style editor with encryption and recovery tools."""
import argparse, base64, getpass, hashlib, json, os, secrets, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

APP="SecurePad Studio"; VERSION="3.0.0"; MAGIC=b"SPADSTUDIO2\n"
DATA=Path.home()/".local/share/securepad-studio"; RECOVERY=DATA/"recovery"; CONFIG=Path.home()/".config/securepad-studio/settings.json"

def derive(passphrase,salt,keyfile=None):
    material=passphrase.encode()
    if keyfile is not None: material=b"SecurePadStudio2\0"+material+b"\0"+hashlib.sha256(keyfile).digest()
    return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(material)

def encrypt_bytes(data,passphrase,keyfile=None,purpose="document"):
    salt,nonce=secrets.token_bytes(16),secrets.token_bytes(12)
    meta={"format":APP,"version":2,"purpose":purpose,"kdf":"scrypt","cipher":"AES-256-GCM",
          "keyfile_required":keyfile is not None,"salt":base64.b64encode(salt).decode(),"nonce":base64.b64encode(nonce).decode()}
    h=json.dumps(meta,separators=(",",":")).encode()
    return MAGIC+len(h).to_bytes(4,"big")+h+AESGCM(derive(passphrase,salt,keyfile)).encrypt(nonce,data,MAGIC+h)

def decrypt_bytes(blob,passphrase,keyfile=None,purpose=None):
    if not blob.startswith(MAGIC) or len(blob)<len(MAGIC)+4: raise ValueError("Not a SecurePad Studio v2 file.")
    p=len(MAGIC); n=int.from_bytes(blob[p:p+4],"big")
    if n>65536 or p+4+n>len(blob): raise ValueError("Invalid file header.")
    h=blob[p+4:p+4+n]; meta=json.loads(h.decode())
    if meta.get("format")!=APP or meta.get("version")!=2: raise ValueError("Unsupported format.")
    if purpose and meta.get("purpose")!=purpose: raise ValueError("Unexpected encrypted-file purpose.")
    if meta.get("keyfile_required") and keyfile is None: raise ValueError("This file requires a key file.")
    if not meta.get("keyfile_required"): keyfile=None
    salt=base64.b64decode(meta["salt"],validate=True); nonce=base64.b64decode(meta["nonce"],validate=True)
    return AESGCM(derive(passphrase,salt,keyfile)).decrypt(nonce,blob[p+4+n:],MAGIC+h),meta

def atomic_write(path,data,backup=True):
    p=Path(path).expanduser(); p.parent.mkdir(parents=True,exist_ok=True)
    if backup and p.exists():
        bdir=DATA/"file-backups"; bdir.mkdir(parents=True,exist_ok=True)
        bp=bdir/(p.name+"."+time.strftime("%Y%m%d-%H%M%S")+".bak")
        try:
            shutil.copy2(p,bp); bp.chmod(0o600)
        except OSError: pass
    fd,tmp=tempfile.mkstemp(prefix="."+p.name+".",dir=str(p.parent))
    try:
        with os.fdopen(fd,"wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,p)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def cli():
    ap=argparse.ArgumentParser(description="SecurePad Studio secure editor / CLI")
    ap.add_argument("--version",action="version",version=VERSION)
    sp=ap.add_subparsers(dest="cmd")
    for name in ("encrypt","decrypt"):
        p=sp.add_parser(name); p.add_argument("input"); p.add_argument("-o","--output",required=True); p.add_argument("--key-file")
    p=sp.add_parser("gpg-encrypt"); p.add_argument("input"); p.add_argument("-o","--output",required=True); p.add_argument("-r","--recipient",required=True)
    p=sp.add_parser("gpg-decrypt"); p.add_argument("input"); p.add_argument("-o","--output",required=True)
    sp.add_parser("gui")
    a=ap.parse_args()
    try:
        if a.cmd in ("encrypt","decrypt"):
            password=getpass.getpass("Passphrase: ")
            key=Path(a.key_file).read_bytes() if a.key_file else None
            if a.cmd=="encrypt":
                if password!=getpass.getpass("Confirm passphrase: "): raise ValueError("Passphrases do not match.")
                atomic_write(a.output,encrypt_bytes(Path(a.input).read_bytes(),password,key),False)
                print("Encrypted:",a.output)
            else:
                raw,_=decrypt_bytes(Path(a.input).read_bytes(),password,key,"document")
                atomic_write(a.output,raw,False); print("Decrypted:",a.output,file=sys.stderr)
                print("WARNING: output is plaintext.",file=sys.stderr)
            return 0
        if a.cmd in ("gpg-encrypt","gpg-decrypt"):
            if not shutil.which("gpg"): raise RuntimeError("Install GnuPG: sudo apt install gnupg")
            cmd=["gpg","--yes","--output",a.output]
            if a.cmd=="gpg-encrypt": cmd += ["--encrypt","--recipient",a.recipient,a.input]
            else: cmd += ["--decrypt",a.input]
            r=subprocess.run(cmd,text=True,capture_output=True)
            if r.returncode: raise RuntimeError((r.stderr or r.stdout).strip())
            print("OpenPGP operation complete:",a.output); return 0
        return None
    except Exception as e:
        print("securepad:",e,file=sys.stderr); return 2

# GUI imports are delayed so CLI can work without a display server.
def launch_gui():
    from PySide6.QtCore import Qt, QTimer, QSize, QRegularExpression
    from PySide6.QtGui import QAction, QFont, QKeySequence, QTextCursor, QTextCharFormat, QColor, QSyntaxHighlighter, QPainter
    from PySide6.QtWidgets import (QApplication,QMainWindow,QPlainTextEdit,QFileDialog,QMessageBox,QInputDialog,
        QLineEdit,QLabel,QStatusBar,QToolBar,QTabWidget,QWidget,QVBoxLayout,QTreeWidget,QTreeWidgetItem,
        QSplitter,QDialog,QDialogButtonBox,QFormLayout,QDockWidget,QPushButton,QHBoxLayout)
    class Highlighter(QSyntaxHighlighter):
        def __init__(self,doc,lang,dark=True):
            super().__init__(doc); self.lang=lang; self.dark=dark
        def highlightBlock(self,text):
            colors={"kw":"#569cd6" if self.dark else "#0000cc","str":"#ce9178" if self.dark else "#a31515",
                    "com":"#6a9955" if self.dark else "#008000","num":"#b5cea8" if self.dark else "#098658"}
            def fmt(c,bold=False,italic=False):
                f=QTextCharFormat(); f.setForeground(QColor(c))
                if bold:f.setFontWeight(QFont.Bold)
                if italic:f.setFontItalic(True)
                return f
            lang=self.lang.lower()
            comment="#" if lang in ("python","shell","yaml","config","toml") else ("--" if lang=="sql" else None)
            if comment and comment in text:
                i=text.find(comment); self.setFormat(i,len(text)-i,fmt(colors["com"],italic=True))
            for pat in (r'"[^"\\]*(?:\\.[^"\\]*)*"',r"'[^'\\]*(?:\\.[^'\\]*)*'"):
                it=QRegularExpression(pat).globalMatch(text)
                while it.hasNext():
                    m=it.next(); self.setFormat(m.capturedStart(),m.capturedLength(),fmt(colors["str"]))
            kws={"python":"and as assert async await break class continue def elif else except False finally for from if import in is lambda None not or pass raise return True try while with yield".split(),
                 "shell":"if then else elif fi for while do done case esac function in".split(),
                 "sql":"SELECT FROM WHERE INSERT INTO VALUES UPDATE SET DELETE CREATE TABLE DROP JOIN ON GROUP BY ORDER LIMIT AND OR NULL".split()}.get(lang,[])
            for kw in kws:
                it=QRegularExpression(r"\b"+kw+r"\b").globalMatch(text)
                while it.hasNext():
                    m=it.next(); self.setFormat(m.capturedStart(),m.capturedLength(),fmt(colors["kw"],True))
            it=QRegularExpression(r"\b\d+(?:\.\d+)?\b").globalMatch(text)
            while it.hasNext():
                m=it.next(); self.setFormat(m.capturedStart(),m.capturedLength(),fmt(colors["num"]))
    class PassDialog(QDialog):
        def __init__(self,title,confirm=False):
            super().__init__(); self.setWindowTitle(title); self.value=""
            lay=QFormLayout(self); self.one=QLineEdit(); self.one.setEchoMode(QLineEdit.Password); lay.addRow("Passphrase:",self.one)
            self.two=None
            if confirm:self.two=QLineEdit(); self.two.setEchoMode(QLineEdit.Password); lay.addRow("Confirm:",self.two)
            self.hint=QLabel("Use a long, unique passphrase."); lay.addRow("",self.hint)
            self.one.textChanged.connect(lambda s:self.hint.setText("Strength: "+("weak" if len(s)<12 else "fair" if len(s)<20 else "good length")))
            buttons=QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel); buttons.accepted.connect(self.check); buttons.rejected.connect(self.reject); lay.addRow(buttons)
        def check(self):
            if not self.one.text() or (self.two is not None and self.one.text()!=self.two.text()):
                QMessageBox.warning(self,"Passphrase","Enter matching non-empty passphrases."); return
            self.value=self.one.text(); self.accept()
    class LineNumberArea(QWidget):
        def __init__(self, editor):
            super().__init__(editor)
            self.editor = editor
        def sizeHint(self):
            return QSize(self.editor.line_number_width(), 0)
        def paintEvent(self, event):
            self.editor.paint_line_numbers(event)

    class Editor(QPlainTextEdit):
        def __init__(self):
            super().__init__()
            self.setLineWrapMode(QPlainTextEdit.NoWrap)
            self.setFont(QFont("DejaVu Sans Mono", 11))
            self.setPlaceholderText("Start writing…")
            self.line_area = LineNumberArea(self)
            self.blockCountChanged.connect(self.update_line_number_width)
            self.updateRequest.connect(self.update_line_number_area)
            self.update_line_number_width()
        def line_number_width(self):
            digits = max(2, len(str(max(1, self.blockCount()))))
            return 14 + self.fontMetrics().horizontalAdvance("9") * digits
        def update_line_number_width(self, *_):
            self.setViewportMargins(self.line_number_width(), 0, 0, 0)
        def update_line_number_area(self, rect, dy):
            if dy:
                self.line_area.scroll(0, dy)
            else:
                self.line_area.update(0, rect.y(), self.line_area.width(), rect.height())
            if rect.contains(self.viewport().rect()):
                self.update_line_number_width()
        def resizeEvent(self, event):
            super().resizeEvent(event)
            cr = self.contentsRect()
            self.line_area.setGeometry(cr.left(), cr.top(), self.line_number_width(), cr.height())
        def paint_line_numbers(self, event):
            painter = QPainter(self.line_area)
            painter.fillRect(event.rect(), QColor("#252526"))
            block = self.firstVisibleBlock()
            number = block.blockNumber()
            top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
            bottom = top + int(self.blockBoundingRect(block).height())
            while block.isValid() and top <= event.rect().bottom():
                if block.isVisible() and bottom >= event.rect().top():
                    painter.setPen(QColor("#858585"))
                    painter.drawText(0, top, self.line_area.width() - 6,
                                     self.fontMetrics().height(), Qt.AlignRight, str(number + 1))
                block = block.next()
                top = bottom
                if block.isValid():
                    bottom = top + int(self.blockBoundingRect(block).height())
                number += 1
    class Win(QMainWindow):
        def __init__(self):
            super().__init__(); self.setWindowTitle(APP+" "+VERSION); self.resize(1480,900); self.docs={}; self.dark=True; self.minimap_visible=True; self.lock_minutes=0; self.lock_hash=None; self.lock_salt=None; self.locked=False
            try:
                cfg=json.loads(CONFIG.read_text()); self.dark=cfg.get("dark",True); self.lock_minutes=cfg.get("lock_minutes",0)
                self.lock_salt=base64.b64decode(cfg["salt"]) if cfg.get("salt") else None; self.lock_hash=base64.b64decode(cfg["hash"]) if cfg.get("hash") else None
            except Exception: pass
            self.tabs=QTabWidget(); self.tabs.setTabsClosable(True); self.tabs.setMovable(True); self.tabs.tabCloseRequested.connect(self.close_tab); self.tabs.currentChanged.connect(self.status_update)
            self.tree=QTreeWidget(); self.tree.setHeaderHidden(True); self.tree.setMinimumWidth(220); self.tree.itemDoubleClicked.connect(self.tree_open); self.fill_tree(str(Path.home()))
            split=QSplitter(); split.addWidget(self.tree); split.addWidget(self.tabs); split.setSizes([250,1100]); self.setCentralWidget(split)
            self.dock=QDockWidget("Security",self); panel=QWidget(); lay=QVBoxLayout(panel)
            self.sec=QLabel("Document security details"); self.sec.setWordWrap(True); lay.addWidget(self.sec)
            for label,fn in [("Save Encrypted…",self.save_enc_as),("Generate Key File…",self.keygen),("Set Lock Password…",self.set_lock),("Lock Editor",self.lock),("Auto-Lock Settings…",self.lock_setting)]:
                b=QPushButton(label); b.clicked.connect(fn); lay.addWidget(b)
            lay.addStretch(); self.dock.setWidget(panel); self.addDockWidget(Qt.RightDockWidgetArea,self.dock)
            self.status=QStatusBar(); self.setStatusBar(self.status); self.stat=QLabel(); self.status.addWidget(self.stat)
            self.menus(); self.toolbar(); self.theme(); self.new_tab()
            self.timer=QTimer(self); self.timer.timeout.connect(self.recovery); self.timer.start(60000)
            self.locktimer=QTimer(self); self.locktimer.timeout.connect(self.auto_lock); self.locktimer.start(10000); self.activity=time.time()
        def save_cfg(self):
            CONFIG.parent.mkdir(parents=True,exist_ok=True); CONFIG.write_text(json.dumps({"dark":self.dark,"lock_minutes":self.lock_minutes,"salt":base64.b64encode(self.lock_salt).decode() if self.lock_salt else None,"hash":base64.b64encode(self.lock_hash).decode() if self.lock_hash else None})); CONFIG.chmod(0o600)
        def menus(self):
            bar=self.menuBar(); fm=bar.addMenu("&File")
            for label,fn,sc in [("New Tab",self.new_tab,"Ctrl+N"),("Open…",self.open_file,"Ctrl+O"),("Open Folder…",self.open_folder,None),("Save",self.save,"Ctrl+S"),("Save As…",self.save_as,"Ctrl+Shift+S"),("Save Encrypted…",self.save_enc_as,"Ctrl+E"),("OpenPGP Encrypt…",self.gpg_enc,None),("OpenPGP Decrypt…",self.gpg_dec,None),("Generate Key File…",self.keygen,None),("Exit",self.close,"Ctrl+Q")]:
                a=QAction(label,self); a.triggered.connect(fn)
                if sc:a.setShortcut(QKeySequence(sc))
                fm.addAction(a)
            em=bar.addMenu("&Edit")
            for label,method,sc in [("Undo","undo","Ctrl+Z"),("Redo","redo","Ctrl+Y"),("Cut","cut","Ctrl+X"),("Copy","copy","Ctrl+C"),("Paste","paste","Ctrl+V"),("Select All","selectAll","Ctrl+A")]:
                a=QAction(label,self); a.setShortcut(QKeySequence(sc)); a.triggered.connect(lambda checked=False,m=method:getattr(self.ed(),m)()); em.addAction(a)
            for label,fn,sc in [("Find…",self.find,"Ctrl+F"),("Replace…",self.replace,"Ctrl+H")]:
                a=QAction(label,self); a.setShortcut(QKeySequence(sc)); a.triggered.connect(fn); em.addAction(a)
            sm=bar.addMenu("&Security")
            for label,fn in [("Set / Change Lock Password",self.set_lock),("Lock Editor",self.lock),("Auto-Lock Settings",self.lock_setting),("Generate Passphrase",self.passgen),("Toggle Read-Only",self.readonly)]:
                a=QAction(label,self); a.triggered.connect(fn); sm.addAction(a)
            vm=bar.addMenu("&View")
            for label,fn,sc in [("Toggle Theme",self.toggle_theme,"Ctrl+K, Ctrl+T"),("Toggle Word Wrap",self.wrap,"Alt+Z"),("Toggle Explorer",lambda:self.tree.setVisible(not self.tree.isVisible()),"Ctrl+B"),("Toggle Minimap",self.toggle_minimap,None),("Recovery Manager…",self.recovery_manager,None),("Toggle Security Panel",lambda:self.dock.setVisible(not self.dock.isVisible()),None)]:
                a=QAction(label,self); a.triggered.connect(fn)
                if sc:a.setShortcut(QKeySequence(sc))
                vm.addAction(a)
        def toolbar(self):
            tb=QToolBar("Activity"); tb.setMovable(False); self.addToolBar(Qt.LeftToolBarArea,tb)
            for label,fn in [("New",self.new_tab),("Open",self.open_file),("Save",self.save),("Encrypt",self.save_enc_as),("Lock",self.lock)]:
                a=QAction(label,self); a.triggered.connect(fn); tb.addAction(a)
        def ed(self):
            w=self.tabs.currentWidget(); return w.findChild(Editor) if w else None
        def doc(self):return self.docs.get(self.ed())
        def lang(self,p):
            return {".py":"Python",".sh":"Shell",".bash":"Shell",".json":"JSON",".yaml":"YAML",".yml":"YAML",".md":"Markdown",".conf":"Config",".ini":"Config",".toml":"TOML",".sql":"SQL"}.get(Path(p).suffix.lower(),"Plain Text") if p else "Plain Text"
        def new_tab(self,text="",path=None,encrypted=False):
            panel=QWidget(); lay=QHBoxLayout(panel); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
            e=Editor(); lay.addWidget(e, 1)
            mini=QPlainTextEdit(); mini.setReadOnly(True); mini.setLineWrapMode(QPlainTextEdit.NoWrap)
            mini.setFont(QFont("DejaVu Sans Mono", 3)); mini.setFixedWidth(110)
            mini.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff); mini.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            mini.setStyleSheet("QPlainTextEdit{border-left:1px solid #3c3c3c;padding:3px;color:#858585;background:#181818;}")
            mini.setVisible(self.minimap_visible); lay.addWidget(mini)
            d={"path":path,"encrypted":encrypted,"dirty":False,"readonly":False,"lang":self.lang(path),
               "minimap":mini,"enc_password":None,"key_bytes":None}
            d["high"]=Highlighter(e.document(),d["lang"],self.dark); self.docs[e]=d
            e.textChanged.connect(lambda ed=e:self.changed(ed))
            e.cursorPositionChanged.connect(self.status_update)
            e.textChanged.connect(lambda ed=e, mm=mini:mm.setPlainText(ed.toPlainText()))
            e.setPlainText(text); mini.setPlainText(text); d["dirty"]=False
            self.tabs.addTab(panel,Path(path).name if path else "Untitled"); self.tabs.setCurrentWidget(panel); self.status_update()
        def changed(self,e):
            d=self.docs[e]; d["dirty"]=True; self.activity=time.time(); i=self.tabs.indexOf(e.parentWidget())
            if i>=0:self.tabs.setTabText(i,(Path(d["path"]).name if d["path"] else "Untitled")+" •")
            self.status_update()
        def status_update(self,*_):
            e=self.ed(); d=self.doc()
            if not e or not d:return
            c=e.textCursor(); self.stat.setText(f"Ln {c.blockNumber()+1}, Col {c.positionInBlock()+1} | {len(e.toPlainText().split())} words | {d['lang']}")
            self.sec.setText(f"Document: {Path(d['path']).name if d['path'] else 'Untitled'}\\nFormat: {'SecurePad .spad' if d['encrypted'] else 'Plain UTF-8'}\\nEncryption: {'AES-256-GCM + scrypt' if d['encrypted'] else 'Not encrypted'}\\nKey file: optional per encrypted document\\nOpenPGP operations use GnuPG; .spad is not EncryptPad-compatible.")
        def fill_tree(self,root):
            self.tree.clear(); base=QTreeWidgetItem([root]); base.setData(0,Qt.UserRole,root); self.tree.addTopLevelItem(base); self.children(base,Path(root),0); base.setExpanded(True)
        def children(self,item,path,depth):
            if depth>1:return
            try:items=sorted(path.iterdir(),key=lambda p:(not p.is_dir(),p.name.lower()))
            except OSError:return
            for p in items[:180]:
                if p.name in {".cache","node_modules",".git","__pycache__"}:continue
                if p.name.startswith(".") and p.name not in {".local",".config"}:continue
                ch=QTreeWidgetItem([p.name]); ch.setData(0,Qt.UserRole,str(p)); item.addChild(ch)
                if p.is_dir():self.children(ch,p,depth+1)
        def tree_open(self,item,col):
            p=Path(item.data(0,Qt.UserRole) or "")
            if p.is_file():self.open_path(str(p))
        def open_folder(self):
            p=QFileDialog.getExistingDirectory(self,"Open Folder",str(Path.home()))
            if p:self.fill_tree(p)
        def open_file(self):
            p,_=QFileDialog.getOpenFileName(self,"Open",str(Path.home()),"SecurePad (*.spad);;Text/source files (*.txt *.py *.sh *.json *.yaml *.md *.conf);;All files (*)")
            if p:self.open_path(p)
        def open_path(self,p):
            try:
                b=Path(p).read_bytes(); enc=b.startswith(MAGIC)
                if enc:
                    dlg=PassDialog("Unlock Document")
                    if dlg.exec()!=QDialog.Accepted:return
                    pos=len(MAGIC); n=int.from_bytes(b[pos:pos+4],"big"); meta=json.loads(b[pos+4:pos+4+n])
                    key=None
                    if meta.get("keyfile_required"):
                        kp,_=QFileDialog.getOpenFileName(self,"Select key file")
                        if not kp:return
                        key=Path(kp).read_bytes()
                    raw,_=decrypt_bytes(b,dlg.value,key,"document"); text=raw.decode()
                else:text=b.decode("utf-8-sig")
                self.new_tab(text,p,enc)
            except Exception as ex:QMessageBox.critical(self,"Open failed",str(ex))
        def current_save(self,path=None,encrypted=False):
            e,d=self.ed(),self.doc()
            if not e:return False
            p=path or d["path"]
            if not p:return self.save_as()
            try:
                if encrypted:
                    password=d.get("enc_password")
                    key=d.get("key_bytes")
                    if password is None:
                        dlg=PassDialog("Encrypt Document",True)
                        if dlg.exec()!=QDialog.Accepted:return False
                        password=dlg.value
                        if QMessageBox.question(self,"Key file","Require a separate key file too?",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes:
                            kp,_=QFileDialog.getOpenFileName(self,"Select key file")
                            if not kp:return False
                            key=Path(kp).read_bytes()
                        d["enc_password"]=password
                        d["key_bytes"]=key
                    data=encrypt_bytes(e.toPlainText().encode(),password,key)
                else:data=e.toPlainText().encode()
                atomic_write(p,data,backup=not encrypted); d.update(path=p,encrypted=encrypted,dirty=False,lang="Encrypted" if encrypted else self.lang(p))
                d["high"].lang=d["lang"]; d["high"].rehighlight()
                self.tabs.setTabText(self.tabs.currentIndex(),Path(p).name);self.status_update()
                return True
            except Exception as ex:QMessageBox.critical(self,"Save failed",str(ex));return False
        def save(self):
            d=self.doc()
            if not d:return False
            return self.current_save(encrypted=True) if d["encrypted"] else self.current_save()
        def save_as(self):
            p,_=QFileDialog.getSaveFileName(self,"Save As",str(Path.home()),"Text files (*.txt);;All files (*)")
            return self.current_save(p,False) if p else False
        def save_enc_as(self):
            p,_=QFileDialog.getSaveFileName(self,"Save Encrypted",str(Path.home()),"SecurePad (*.spad)")
            if p:
                if not p.endswith(".spad"):p+=".spad"
                return self.current_save(p,True)
            return False
        def close_tab(self,i):
            panel=self.tabs.widget(i); e=panel.findChild(Editor); d=self.docs.get(e)
            if d and d["dirty"]:
                ans=QMessageBox.question(self,"Unsaved","Save changes?",QMessageBox.Save|QMessageBox.Discard|QMessageBox.Cancel)
                if ans==QMessageBox.Cancel:return
                if ans==QMessageBox.Save:
                    self.tabs.setCurrentWidget(panel)
                    if not self.save():return
            self.docs.pop(e,None);self.tabs.removeTab(i);panel.deleteLater()
            if self.tabs.count()==0:self.new_tab()
        def find(self):
            q,ok=QInputDialog.getText(self,"Find","Find:")
            if ok and q and not self.ed().find(q):
                c=self.ed().textCursor();c.movePosition(QTextCursor.Start);self.ed().setTextCursor(c)
                if not self.ed().find(q):QMessageBox.information(self,"Find","Not found.")
        def replace(self):
            old,ok=QInputDialog.getText(self,"Replace","Find:")
            if not ok or not old:return
            new,ok=QInputDialog.getText(self,"Replace","Replace with:")
            if ok:
                e=self.ed();txt=e.toPlainText();n=txt.count(old)
                if n:e.setPlainText(txt.replace(old,new));QMessageBox.information(self,"Replace",f"Replaced {n} occurrence(s).")
        def keygen(self):
            p,_=QFileDialog.getSaveFileName(self,"Generate Key File",str(Path.home()/"securepad.key"),"Key files (*.key)")
            if p:atomic_write(p,secrets.token_bytes(32),False);QMessageBox.information(self,"Key","Created random 256-bit key file. Store separately.")
        def passgen(self):
            a="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%+-_"; s="-".join("".join(secrets.choice(a) for _ in range(5)) for _ in range(6));QMessageBox.information(self,"Passphrase",s+"\\nStore in a password manager.")
        def readonly(self):
            e,d=self.ed(),self.doc()
            if e and d:d["readonly"]=not d["readonly"];e.setReadOnly(d["readonly"])
        def wrap(self):
            e=self.ed()
            if e:e.setLineWrapMode(QPlainTextEdit.WidgetWidth if e.lineWrapMode()==QPlainTextEdit.NoWrap else QPlainTextEdit.NoWrap)
        def toggle_minimap(self):
            self.minimap_visible=not self.minimap_visible
            for d in self.docs.values():
                d["minimap"].setVisible(self.minimap_visible)
        def recovery_manager(self):
            from PySide6.QtWidgets import QListWidget
            RECOVERY.mkdir(parents=True, exist_ok=True)
            files=sorted(RECOVERY.glob("*.recovery"), key=lambda p:p.stat().st_mtime, reverse=True)
            if not files:
                QMessageBox.information(self,"Recovery Manager","No recovery snapshots were found yet. Snapshots are created for modified documents during the recovery interval.")
                return
            dlg=QDialog(self); dlg.setWindowTitle("Recovery Manager"); dlg.resize(720,440)
            lay=QVBoxLayout(dlg); listing=QListWidget(); lay.addWidget(listing)
            keypath=DATA/"recovery.key"
            def describe(f):
                try:
                    k=base64.b64encode(keypath.read_bytes()).decode()
                    raw,_=decrypt_bytes(f.read_bytes(),k,purpose="recovery")
                    info=json.loads(raw.decode())
                    stamp=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(info.get("time",f.stat().st_mtime)))
                    return f"{stamp} — {Path(info.get('path') or f.stem).name}"
                except Exception:
                    return f"{f.name} — unreadable snapshot"
            for f in files: listing.addItem(describe(f))
            row=QHBoxLayout(); restore=QPushButton("Restore into New Tab"); delete=QPushButton("Delete Snapshot"); close=QPushButton("Close")
            row.addWidget(restore); row.addWidget(delete); row.addStretch(); row.addWidget(close); lay.addLayout(row)
            def selected():
                i=listing.currentRow()
                return files[i] if 0 <= i < len(files) else None
            def restore_selected():
                f=selected()
                if not f: return
                try:
                    k=base64.b64encode(keypath.read_bytes()).decode()
                    raw,_=decrypt_bytes(f.read_bytes(),k,purpose="recovery")
                    info=json.loads(raw.decode())
                    self.new_tab(info.get("text",""),info.get("path"),False)
                    self.status.showMessage("Recovery restored into a new tab. Save it explicitly.",8000)
                    dlg.accept()
                except Exception as ex:
                    QMessageBox.critical(dlg,"Restore failed",str(ex))
            def delete_selected():
                f=selected()
                if not f: return
                if QMessageBox.question(dlg,"Delete Snapshot",f"Delete {f.name}?",QMessageBox.Yes|QMessageBox.No)==QMessageBox.Yes:
                    f.unlink(missing_ok=True)
                    listing.takeItem(listing.currentRow())
                    files.remove(f)
            restore.clicked.connect(restore_selected); delete.clicked.connect(delete_selected); close.clicked.connect(dlg.reject)
            dlg.exec()
        def toggle_theme(self):
            self.dark=not self.dark
            for d in self.docs.values():d["high"].dark=self.dark;d["high"].rehighlight()
            self.theme();self.save_cfg()
        def theme(self):
            self.setStyleSheet("""QMainWindow,QMenuBar,QMenu,QToolBar,QStatusBar,QTreeWidget,QDockWidget,QTabWidget::pane{background:#1e1e1e;color:#d4d4d4;} QPlainTextEdit{background:#1e1e1e;color:#d4d4d4;selection-background-color:#264f78;border:0;padding:8px;} QMenu::item:selected{background:#094771;} QTabBar::tab{background:#2d2d2d;color:#ccc;padding:8px 14px;} QTabBar::tab:selected{background:#1e1e1e;border-top:2px solid #007acc;}""" if self.dark else "")
        def set_lock(self):
            dlg=PassDialog("Set Lock Password",True)
            if dlg.exec()!=QDialog.Accepted:return
            self.lock_salt=secrets.token_bytes(16);self.lock_hash=derive(dlg.value,self.lock_salt);self.save_cfg();QMessageBox.information(self,"Lock password","Lock password configured.")
        def lock_setting(self):
            n,ok=QInputDialog.getInt(self,"Auto-Lock","Minutes of inactivity (0 disables):",self.lock_minutes,0,240)
            if ok:self.lock_minutes=n;self.save_cfg()
        def auto_lock(self):
            if self.lock_minutes and not self.locked and time.time()-self.activity>=self.lock_minutes*60:self.lock()
        def lock(self):
            if self.locked:return
            if not self.lock_hash:QMessageBox.information(self,"Set password","Configure a lock password first.");return
            for e in self.docs:e.setVisible(False)
            self.lock_page=QWidget();lay=QVBoxLayout(self.lock_page);lab=QLabel("SecurePad Studio is locked");lab.setAlignment(Qt.AlignCenter);lay.addWidget(lab)
            field=QLineEdit();field.setEchoMode(QLineEdit.Password);field.setPlaceholderText("Lock password");lay.addWidget(field)
            btn=QPushButton("Unlock");btn.clicked.connect(lambda:self.unlock(field.text()));field.returnPressed.connect(lambda:self.unlock(field.text()));lay.addWidget(btn)
            self.tabs.addTab(self.lock_page,"Locked");self.tabs.setCurrentWidget(self.lock_page);self.locked=True
        def unlock(self,pw):
            try: got=derive(pw,self.lock_salt)
            except Exception:got=b""
            if not secrets.compare_digest(got,self.lock_hash):QMessageBox.warning(self,"Unlock","Incorrect password.");return
            self.tabs.removeTab(self.tabs.indexOf(self.lock_page))
            for e in self.docs:e.setVisible(True)
            self.locked=False;self.activity=time.time();self.tabs.setCurrentIndex(0)
        def recovery(self):
            # Recovery blobs are encrypted with a local random key. This protects casual inspection,
            # but not a malicious process running as the same account.
            try:
                DATA.mkdir(parents=True,exist_ok=True);kp=DATA/"recovery.key"
                if not kp.exists():atomic_write(kp,secrets.token_bytes(32),False);kp.chmod(0o600)
                k=base64.b64encode(kp.read_bytes()).decode();RECOVERY.mkdir(parents=True,exist_ok=True)
                for e,d in self.docs.items():
                    if d["dirty"]:
                        name=Path(d["path"]).name if d["path"] else "untitled-"+str(id(e))
                        safe="".join(c if c.isalnum() or c in "._-" else "_" for c in name)
                        raw=json.dumps({"path":d["path"],"text":e.toPlainText(),"time":time.time()}).encode()
                        target=RECOVERY/(safe+".recovery");atomic_write(target,encrypt_bytes(raw,k,purpose="recovery"),False);target.chmod(0o600)
            except OSError:pass
        def gpg_enc(self):
            if not shutil.which("gpg"):QMessageBox.warning(self,"GnuPG","Install with sudo apt install gnupg");return
            src,_=QFileDialog.getOpenFileName(self,"Select file to encrypt")
            if not src:return
            rec,ok=QInputDialog.getText(self,"Recipient","GPG key ID or email:")
            if not ok or not rec:return
            out,_=QFileDialog.getSaveFileName(self,"Save encrypted",src+".gpg","OpenPGP (*.gpg)")
            if out:
                r=subprocess.run(["gpg","--yes","--output",out,"--encrypt","--recipient",rec,src],capture_output=True,text=True)
                if r.returncode:QMessageBox.critical(self,"GPG",r.stderr[-2000:])
                else:QMessageBox.information(self,"GPG","Encrypted.")
        def gpg_dec(self):
            if not shutil.which("gpg"):QMessageBox.warning(self,"GnuPG","Install with sudo apt install gnupg");return
            src,_=QFileDialog.getOpenFileName(self,"Select OpenPGP file")
            if not src:return
            out,_=QFileDialog.getSaveFileName(self,"Save plaintext",str(Path(src).with_suffix(".txt")))
            if out:
                r=subprocess.run(["gpg","--yes","--output",out,"--decrypt",src],capture_output=True,text=True)
                if r.returncode:QMessageBox.critical(self,"GPG",r.stderr[-2000:])
                else:QMessageBox.warning(self,"Plaintext","Decrypted output is plaintext.")
        def closeEvent(self,event):
            for e,d in list(self.docs.items()):
                if d["dirty"]:
                    ans=QMessageBox.question(self,"Unsaved","Save changes before exit?",QMessageBox.Save|QMessageBox.Discard|QMessageBox.Cancel)
                    if ans==QMessageBox.Cancel:event.ignore();return
                    if ans==QMessageBox.Save:
                        self.tabs.setCurrentWidget(e.parentWidget())
                        if not self.save():event.ignore();return
            event.accept()
    app=QApplication(sys.argv); w=Win(); w.show(); sys.exit(app.exec())

def main():
    a=cli()
    if a is not None:return a
    launch_gui()

if __name__=="__main__":sys.exit(main() or 0)
