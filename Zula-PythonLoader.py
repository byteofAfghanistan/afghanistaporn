#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modern dependency-free Windows UI for the existing Zula launch pipeline."""
from __future__ import annotations
import base64, hashlib, json, os, queue, re, socket, ssl, subprocess, sys, threading, time
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

TITLE="ZULA // PRIVATE NETWORK LOADER"; VERSION="2.0.0"; DEFAULT_SERVER="172.31.205.20"; PORT=443
SNI="zulaoyun.com"; DEFAULT_PIN="8uDkBnjiJ9eLbGDd/8W50v9uj/Tl+zVivsZ6wde90JA="
@dataclass(frozen=True)
class Account: player_id:int; nickname:str; identity:Path; digest:str
class LoaderError(Exception): pass

class App(tk.Tk):
    BG="#0b0f14"; PANEL="#111821"; P2="#151f2a"; BORDER="#243242"; TEXT="#e8eef5"; MUTED="#8192a5"; ACCENT="#67e8f9"; GOOD="#5ee6a8"; WARN="#f9d66b"; BAD="#ff7d8c"
    def __init__(self):
        super().__init__(); self.title(TITLE); self.geometry("1120x720"); self.minsize(940,620); self.configure(bg=self.BG)
        self.workspace=self.find_workspace(); self.server=tk.StringVar(value=DEFAULT_SERVER); self.accounts=[]; self.selected=None; self.proc=None; self.busy=False
        self.logq=queue.Queue(); self.uiq=queue.Queue(); self.make_styles(); self.ui(); self.after(100,self.pump); self.load_accounts(); self.protocol("WM_DELETE_WINDOW",self.close)
        self.log(f"{TITLE} v{VERSION}","accent"); self.log(f"WORKSPACE  {self.workspace}")
    @staticmethod
    def find_workspace():
        here=Path(__file__).resolve().parent; c=[here]
        if os.environ.get("ZULA_WORKSPACE"): c.append(Path(os.environ["ZULA_WORKSPACE"]))
        c += [Path(r"C:\ZulaServer\Server"),Path.cwd()]
        for p in c:
            try:
                if (p/"tools"/"Zula-Launcher.ps1").is_file(): return p.resolve()
            except OSError: pass
        return here.resolve()
    def P(self,*x): return self.workspace.joinpath(*x)
    def make_styles(self):
        s=ttk.Style(self)
        try:s.theme_use("clam")
        except tk.TclError:pass
        s.configure("Z.TEntry",fieldbackground=self.P2,background=self.P2,foreground=self.TEXT,bordercolor=self.BORDER,lightcolor=self.BORDER,darkcolor=self.BORDER,insertcolor=self.ACCENT,padding=8,font=("Segoe UI",10))
        s.configure("Z.Scroll",troughcolor=self.P2,background=self.BORDER,bordercolor=self.P2)
    def button(self,p,t,cmd,w=12,primary=False):
        return tk.Button(p,text=t,command=cmd,width=w,bg="#1c2d3c" if primary else self.P2,fg=self.ACCENT if primary else self.TEXT,activebackground="#284256",activeforeground=self.TEXT,relief="flat",bd=0,cursor="hand2",font=("Consolas",9,"bold"),padx=8,pady=8)
    def ui(self):
        self.grid_columnconfigure(1,weight=1); self.grid_rowconfigure(1,weight=1)
        h=tk.Frame(self,bg=self.BG); h.grid(row=0,column=0,columnspan=2,sticky="ew",padx=24,pady=(18,10)); h.grid_columnconfigure(1,weight=1)
        b=tk.Frame(h,bg=self.BG); b.grid(row=0,column=0,sticky="w"); tk.Label(b,text="ZULA",bg=self.BG,fg=self.TEXT,font=("Segoe UI Black",24)).pack(anchor="w"); tk.Label(b,text="PRIVATE NETWORK // LOADER",bg=self.BG,fg=self.ACCENT,font=("Consolas",9,"bold")).pack(anchor="w")
        self.state=tk.Label(h,text="INITIALIZING",bg=self.BG,fg=self.MUTED,font=("Consolas",10,"bold")); self.state.grid(row=0,column=1)
        pill=tk.Frame(h,bg=self.PANEL,highlightthickness=1,highlightbackground=self.BORDER); pill.grid(row=0,column=2,sticky="e"); self.dot=tk.Label(pill,text="●",bg=self.PANEL,fg=self.WARN); self.dot.pack(side="left",padx=(10,2),pady=8); self.pill=tk.Label(pill,text="CHECKING",bg=self.PANEL,fg=self.TEXT,font=("Consolas",9,"bold")); self.pill.pack(side="left",padx=(0,10))
        side=tk.Frame(self,bg=self.BG); side.grid(row=1,column=0,sticky="nsw",padx=(24,12),pady=(0,18)); side.grid_rowconfigure(1,weight=1)
        main=tk.Frame(self,bg=self.BG); main.grid(row=1,column=1,sticky="nsew",padx=(0,24),pady=(0,18)); main.grid_rowconfigure(1,weight=1); main.grid_columnconfigure(0,weight=1)
        self.node(side); self.accounts_ui(side); self.main_ui(main)
    def panel(self,p,title,sub=None):
        f=tk.Frame(p,bg=self.PANEL,highlightthickness=1,highlightbackground=self.BORDER); f.pack(fill="both",expand=True,pady=(0,12)); tk.Label(f,text=title,bg=self.PANEL,fg=self.TEXT,font=("Segoe UI Semibold",11)).pack(anchor="w",padx=15,pady=(13,3));
        if sub:tk.Label(f,text=sub,bg=self.PANEL,fg=self.MUTED,font=("Segoe UI",8)).pack(anchor="w",padx=15,pady=(0,8))
        return f
    def node(self,p):
        f=self.panel(p,"NODE","Same IPv4 contract as the existing PowerShell launcher."); r=tk.Frame(f,bg=self.PANEL); r.pack(fill="x",padx=15,pady=(0,15)); tk.Label(r,text="SERVER IPv4",bg=self.PANEL,fg=self.MUTED,font=("Consolas",8,"bold")).pack(anchor="w"); x=tk.Frame(r,bg=self.PANEL); x.pack(fill="x",pady=(4,0)); self.entry=ttk.Entry(x,textvariable=self.server,style="Z.TEntry"); self.entry.pack(side="left",fill="x",expand=True); self.verify=self.button(x,"VERIFY",self.verify_async,9); self.verify.pack(side="left",padx=(7,0))
    def accounts_ui(self,p):
        f=tk.Frame(p,bg=self.PANEL,highlightthickness=1,highlightbackground=self.BORDER); f.grid(row=1,column=0,sticky="nsew"); tk.Label(f,text="ACCOUNTS",bg=self.PANEL,fg=self.TEXT,font=("Segoe UI Semibold",11)).pack(anchor="w",padx=15,pady=(13,2)); tk.Label(f,text="remote-client*.json",bg=self.PANEL,fg=self.MUTED,font=("Consolas",8)).pack(anchor="w",padx=15,pady=(0,8))
        self.list=tk.Listbox(f,bg=self.P2,fg=self.TEXT,selectbackground="#213140",selectforeground=self.TEXT,activestyle="none",relief="flat",highlightthickness=0,font=("Segoe UI Semibold",10),bd=0); self.list.pack(fill="both",expand=True,padx=9,pady=(0,8)); self.list.bind("<<ListboxSelect>>",self.select)
        self.meta=tk.Label(f,text="No account selected",bg=self.PANEL,fg=self.MUTED,font=("Consolas",8)); self.meta.pack(anchor="w",padx=15,pady=(0,10)); self.refresh=self.button(f,"REFRESH ACCOUNTS",self.load_accounts); self.refresh.pack(fill="x",padx=15,pady=(0,15))
    def main_ui(self,p):
        hero=tk.Frame(p,bg=self.BG); hero.grid(row=0,column=0,sticky="ew",pady=(0,12)); hero.grid_columnconfigure(0,weight=1); self.hero=tk.Label(hero,text="READY FOR SESSION",bg=self.BG,fg=self.TEXT,font=("Segoe UI Black",22)); self.hero.grid(row=0,column=0,sticky="w"); self.sub=tk.Label(hero,text="Select an account and verify the node before launch.",bg=self.BG,fg=self.MUTED,font=("Segoe UI",9)); self.sub.grid(row=1,column=0,sticky="w",pady=(3,0)); c=tk.Frame(hero,bg=self.BG); c.grid(row=0,column=1,rowspan=2,sticky="e"); self.start=self.button(c,"LAUNCH SESSION",self.launch,17,True); self.start.pack(side="left",padx=(0,8)); self.stop=self.button(c,"STOP",self.stop_session,9); self.stop.pack(side="left")
        d=tk.Frame(p,bg=self.PANEL,highlightthickness=1,highlightbackground=self.BORDER); d.grid(row=1,column=0,sticky="nsew"); d.grid_rowconfigure(1,weight=1); d.grid_columnconfigure(0,weight=1); tk.Label(d,text="DIAGNOSTICS",bg=self.PANEL,fg=self.TEXT,font=("Segoe UI Semibold",11)).grid(row=0,column=0,sticky="w",padx=14,pady=(11,4)); self.diag=tk.Label(d,text="Preflight not run yet.",bg=self.PANEL,fg=self.TEXT,font=("Consolas",8),anchor="w",justify="left"); self.diag.grid(row=1,column=0,sticky="new",padx=14)
        self.console=tk.Text(d,bg="#0a0e13",fg="#b9c7d6",insertbackground=self.ACCENT,font=("Consolas",9),relief="flat",bd=0,highlightthickness=0,state="disabled",wrap="word"); self.console.grid(row=2,column=0,sticky="nsew",padx=12,pady=(10,12)); d.grid_rowconfigure(2,weight=2); [self.console.tag_configure(t,foreground=c) for t,c in (("info","#b9c7d6"),("accent",self.ACCENT),("good",self.GOOD),("warn",self.WARN),("bad",self.BAD))]
    def log(self,msg,level="info"):self.logq.put((level,msg))
    def set_state(self,t,good=None):self.state.config(text=t.upper()); self.pill.config(text=t.upper()); self.dot.config(fg=self.GOOD if good is True else self.BAD if good is False else self.WARN)
    def pump(self):
        while 1:
            try:l,m=self.logq.get_nowait()
            except queue.Empty:break
            self.console.config(state="normal"); self.console.insert("end",f"[{time.strftime('%H:%M:%S')}] {m}\n",l); self.console.see("end"); self.console.config(state="disabled")
        while 1:
            try:a,p=self.uiq.get_nowait()
            except queue.Empty:break
            if a=="accounts":self.apply_accounts(p)
            elif a=="preflight":self.apply_preflight(*p)
            elif a=="status":self.set_state(p)
            elif a=="done":self.done(p)
            elif a=="controls":self.controls(p)
            elif a=="error":messagebox.showerror("Zula Loader",str(p))
        self.after(120,self.pump)
    def load_accounts(self):threading.Thread(target=self.account_worker,daemon=True).start()
    def account_worker(self):
        out=[]; seen=set(); data=self.P("data")
        if data.is_dir():
            for p in sorted(data.glob("remote-client*.json"),key=lambda x:x.name.lower()):
                try:
                    a=self.read_account(p)
                    if a.player_id not in seen:seen.add(a.player_id);out.append(a)
                except Exception as e:self.log(f"Skipped {p.name}: {e}","warn")
        out.sort(key=lambda x:x.player_id); self.uiq.put(("accounts",out)); self.uiq.put(("controls",True))
    @staticmethod
    def read_account(p):
        raw=p.read_bytes(); obj=json.loads((raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw).decode("utf-8")); pid=int(obj["Id"]); nick=str(obj["NickName"]).strip(); token=str(obj["Token"])
        if not 1<=pid<=2147483647 or not nick or len(nick)>64 or re.search(r"[\x00-\x1f\x7f]",nick) or not re.fullmatch(r"[\x21-\x7e]{32,128}",token):raise LoaderError("invalid account JSON")
        return Account(pid,nick,p.resolve(),base64.b64encode(hashlib.sha256(raw).digest()).decode())
    def apply_accounts(self,a):
        self.accounts=a; self.list.delete(0,"end")
        for x in a:self.list.insert("end",f"  {x.nickname}   ·   ID {x.player_id}")
        if a:self.list.selection_set(0);self.list.event_generate("<<ListboxSelect>>");self.log(f"Loaded {len(a)} account(s).","good");self.set_state("READY",True)
        else:self.selected=None;self.meta.config(text="No valid account files found.");self.set_state("NO ACCOUNT",False)
    def select(self,_=None):
        s=self.list.curselection()
        if not s:return
        self.selected=self.accounts[s[0]]; self.meta.config(text=f"PLAYER {self.selected.player_id}  ·  {self.selected.nickname}"); self.hero.config(text=f"READY / {self.selected.nickname.upper()}")
    @staticmethod
    def ipv4(v):
        p=v.split(".")
        try:n=[int(x) for x in p]
        except ValueError:raise LoaderError("SERVER must be a dotted IPv4")
        if len(p)!=4 or any(str(x)!=s for x,s in zip(n,p)) or any(x<0 or x>255 for x in n) or n[0]==0 or n[0]>=224:raise LoaderError("Invalid IPv4 server address")
        return v
    def powershell(self):
        p=Path(os.environ.get("WINDIR",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe";return str(p) if p.is_file() else None
    def which(self,n):
        for q in os.environ.get("PATH","").split(os.pathsep):
            if q and (Path(q)/n).is_file():return str(Path(q)/n)
        return None
    def game_exe(self):
        ps=self.P("tools","Zula-ProcessTools.ps1")
        if not ps.is_file():return None
        m=re.search(r'(?m)^GAME_DIR\s*=\s*r"([^"\r\n]+)"\s*$',ps.read_text(encoding="utf-8",errors="replace")); p=Path(m.group(1))/"zula.exe" if m else None; return str(p) if p and p.is_file() else None
    def expected_pin(self):
        p=self.P("UpdateTrust.cs")
        if p.is_file():
            m=re.search(r'CertificateSha256\s*=\s*"([^"]+)"',p.read_text(encoding="utf-8",errors="replace"));
            if m:return m.group(1)
        return DEFAULT_PIN
    def tls_pin(self,server):
        try:sock=socket.create_connection((server,PORT),timeout=4)
        except OSError as e:return False,f"TCP failed: {e}"
        try:
            c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);c.check_hostname=False;c.verify_mode=ssl.CERT_NONE
            with c.wrap_socket(sock,server_hostname=SNI) as s:der=s.getpeercert(binary_form=True)
            got=base64.b64encode(hashlib.sha256(der).digest()).decode();exp=self.expected_pin();return got==exp,(f"TLS SHA-256 pin matched: {got}" if got==exp else f"TLS pin mismatch: got {got}, expected {exp}")
        except (ssl.SSLError,OSError) as e:return False,f"TLS handshake failed: {e}"
    def preflight(self,server):
        req=["tools/Zula-Start.ps1","tools/Zula-Launcher.ps1","tools/Zula-LaunchArguments.ps1","tools/Zula-ProcessTools.ps1","tools/Set-ZulaHosts.ps1","tools/Restore-ZulaHosts.ps1","tools/frida_play_connect.py","tools/install_source_art.py","tools/install_source_textures.py","tools/check_remote_zula_ready.js","certs/server.crt"]; miss=[x for x in req if not self.P(*x.split("/" )).is_file()]
        rows=[f"NODE       {server}:{PORT}",f"POWERSHELL {self.powershell() or 'MISSING'}",f"NODE.JS    {self.which('node.exe') or 'MISSING'}",f"GAME       {self.game_exe() or 'MISSING'}",f"FILES      {len(req)-len(miss)}/{len(req)} ready"]
        if miss:return False,"\n".join(rows+["MISSING: "+", ".join(miss)])
        ok,msg=self.tls_pin(server);return ok,"\n".join(rows+["TLS        "+("PIN MATCH" if ok else "PIN FAILED"),"TLS: "+msg])
    def verify_async(self):
        if self.busy:return
        try:s=self.ipv4(self.server.get().strip())
        except LoaderError as e:messagebox.showerror("Zula Loader",str(e));return
        self.busy=True;self.set_state("VERIFYING");threading.Thread(target=self.verify_worker,args=(s,),daemon=True).start()
    def verify_worker(self,s):
        try:self.uiq.put(("preflight",self.preflight(s)))
        finally:self.busy=False;self.uiq.put(("controls",True))
    def apply_preflight(self,ok,report):self.diag.config(text=report);self.set_state("NODE ONLINE" if ok else "NODE OFFLINE",ok);self.log("Preflight passed." if ok else "Preflight failed.","good" if ok else "bad")
    def launch(self):
        if self.busy or self.proc or not self.selected:
            if not self.selected:messagebox.showwarning("Zula Loader","Önce bir hesap seç.")
            return
        try:s=self.ipv4(self.server.get().strip())
        except LoaderError as e:messagebox.showerror("Zula Loader",str(e));return
        self.busy=True;self.controls(False);self.set_state("STARTING");self.log(f"Launching {self.selected.nickname} -> {s}:{PORT}","accent");threading.Thread(target=self.launch_worker,args=(self.selected,s),daemon=True).start()
    def launch_worker(self,a,s):
        code=1
        try:
            ps=self.powershell(); script=self.P("tools","Zula-Start.ps1")
            if not ps or not script.is_file():raise LoaderError("Start pipeline unavailable")
            env=os.environ.copy();env["PYTHONIOENCODING"]="utf-8";env["PYTHONUNBUFFERED"]="1"
            self.proc=subprocess.Popen([ps,"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",str(script),"--server",s,"--identity",str(a.identity)],cwd=str(self.workspace),env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding="utf-8",errors="replace",creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            for raw in self.proc.stdout or []:
                line=raw.rstrip();
                if line:self.log(line,self.level(line));self.uiq.put(("status",self.line_status(line)))
            code=self.proc.wait()
        except Exception as e:self.log(f"Launch error: {e}","bad");self.uiq.put(("error",e))
        finally:self.proc=None;self.busy=False;self.uiq.put(("done",code))
    def stop_session(self):
        if self.proc:
            try:self.proc.terminate()
            except OSError:pass
        threading.Thread(target=self.stop_worker,daemon=True).start()
    def stop_worker(self):
        try:
            ps=self.powershell();script=self.P("tools","Zula-Launcher.ps1")
            if not ps or not script.is_file():raise LoaderError("Stop pipeline unavailable")
            p=subprocess.Popen([ps,"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",str(script),"-Action","StopClient","-Workspace",str(self.workspace)],cwd=str(self.workspace),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding="utf-8",errors="replace",creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            for raw in p.stdout or []:
                line=raw.rstrip();
                if line:self.log(line,self.level(line))
            self.log(f"Stop pipeline exit code: {p.wait()}","good")
        except Exception as e:self.log(f"Stop error: {e}","bad")
    def done(self,c):self.controls(True);self.set_state("SESSION CLOSED",True) if c==0 else self.set_state("SESSION ERROR",False);self.hero.config(text="SESSION COMPLETE" if c==0 else "SESSION INTERRUPTED")
    def controls(self,on):
        st="normal" if on else "disabled";self.start.config(state=st);self.verify.config(state=st);self.refresh.config(state=st);self.entry.config(state=st);self.list.config(state=st);self.stop.config(state="normal")
    @staticmethod
    def level(x):
        x=x.lower();return "bad" if any(a in x for a in ("[hata]","[fatal]","exception","failed")) else "good" if any(a in x for a in ("[hazir]","[tamam]","resume")) else "accent" if any(a in x for a in ("tls","hosts","server")) else "info"
    @staticmethod
    def line_status(x):
        x=x.lower();return "VERIFYING SERVER" if "yalniz istemci" in x else "SERVER READY" if "[hazir]" in x else "NETWORK ROUTED" if "[hosts]" in x else "LAUNCHING GAME" if "uzak istemci baslatiliyor" in x else "GAME PROCESS" if "[sys] zula pid=" in x else "SESSION LIVE" if "[sys] resume" in x else "ERROR" if "[hata]" in x or "[fatal]" in x else "LAUNCH PIPELINE"
    def close(self):
        if self.proc and not messagebox.askyesno("Zula Loader","Aktif oturum var. Kapatılsın mı?"):return
        if self.proc:
            try:self.proc.terminate()
            except OSError:pass
        self.destroy()

def main():
    if sys.platform!="win32":print("Windows only",file=sys.stderr);return
    App().mainloop()
if __name__=="__main__":main()
