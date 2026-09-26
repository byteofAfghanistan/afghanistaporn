using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Xml;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ZulaLoader
{
    public enum LauncherState
    {
        Idle,
        Starting,
        Running,
        Stopping,
        Error
    }

    public sealed class AccountChoice
    {
        public long PlayerId { get; private set; }
        public string Nickname { get; private set; }
        public string IdentityPath { get; private set; }
        public string Digest { get; private set; }

        public AccountChoice(long playerId, string nickname, string identityPath, string digest)
        {
            PlayerId = playerId;
            Nickname = nickname;
            IdentityPath = identityPath;
            Digest = digest;
        }

        public override string ToString()
        {
            return Nickname;
        }
    }

    public sealed class LauncherBridge : IDisposable
    {
        public const string DefaultServer = "172.31.205.20";
        public const int DefaultPort = 443;

        public static HttpClient CreateClient()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

            var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add("User-Agent", "ZulaLoader-Agent/1.0");
            return client;
        }

        private readonly object sync = new object();
        private readonly ManualResetEvent operationDone = new ManualResetEvent(true);
        private readonly Dictionary<string, AccountChoice> accounts = new Dictionary<string, AccountChoice>(StringComparer.OrdinalIgnoreCase);
        private LauncherState state = LauncherState.Idle;
        private bool busy, stopRequested, disposed, gameRunning;
        private OwnedJob launchJob;
        private EventWaitHandle launchStop;
        private long stopStarted;
        private string lastMessage;
        private SessionDiagnostics diagnostics;
        public string LastDiagnosticLogPath { get; private set; }
        public string Workspace { get; private set; }
        public event Action<string> Status;
        public event Action<LauncherState, string> StatusChanged;
        public event Action<int> Completed;
        public LauncherState State { get { lock (sync) { return state; } } }
        public bool IsBusy { get { lock (sync) { return busy; } } }
        public bool IsRunning { get { return IsBusy; } }
        public bool IsGameRunning { get { lock (sync) { return gameRunning; } } }

        public LauncherBridge(string workspace)
        {
            if (String.IsNullOrWhiteSpace(workspace)) throw new ArgumentException("Kurulum klasörü bulunamadı.");
            Workspace = Path.GetFullPath(workspace).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            RequireOrdinaryDirectory(Workspace);
            RequireOrdinaryDirectory(Path.Combine(Workspace, "tools"));
        }

        public IList<AccountChoice> LoadAccounts()
        {
            lock (sync)
            {
                ThrowIfDisposed();
                if (busy) throw new InvalidOperationException("Oyun açıkken hesaplar yenilenemez.");
                accounts.Clear();
                string directory = Path.Combine(Workspace, "data");
                if (!Directory.Exists(directory)) return new List<AccountChoice>().AsReadOnly();
                RequireOrdinaryDirectory(directory);
                string[] files = Directory.GetFiles(directory, "remote-client*.json", SearchOption.TopDirectoryOnly);
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                HashSet<long> ids = new HashSet<long>();
                List<AccountChoice> result = new List<AccountChoice>();
                foreach (string file in files)
                {
                    if (!Regex.IsMatch(Path.GetFileName(file), @"\Aremote-client[A-Za-z0-9_-]*\.json\z", RegexOptions.IgnoreCase)) continue;
                    try
                    {
                        AccountChoice account = ReadAccount(file);
                        if (!ids.Add(account.PlayerId)) continue;
                        accounts.Add(account.IdentityPath, account);
                        result.Add(account);
                    }
                    catch (Exception error)
                    {
                        if (!(error is IOException || error is UnauthorizedAccessException || error is ArgumentException || error is InvalidOperationException || error is FormatException)) throw;
                                                                                    
                    }
                }
                result.Sort(delegate(AccountChoice a, AccountChoice b) { return a.PlayerId.CompareTo(b.PlayerId); });
                return result.AsReadOnly();
            }
        }

        internal string ReadAccountPassword(AccountChoice account)
        {
            lock (sync) {
                ThrowIfDisposed();
                if (busy) throw new InvalidOperationException("Oyun açıkken hesap bilgisi değiştirilemez.");
                AccountChoice known;
                if (account == null || !accounts.TryGetValue(account.IdentityPath, out known) || !Object.ReferenceEquals(account, known))
                    throw new ArgumentException("Geçerli bir hesap seçin.");
                string password;
                AccountChoice current = ReadAccount(account.IdentityPath, out password);
                if (!String.Equals(current.Digest, account.Digest, StringComparison.Ordinal))
                    throw new InvalidOperationException("Hesap dosyası değişti.");
                return password;
            }
        }

        internal long ReadSelectedAccountId()
        {
            lock (sync) {
                ThrowIfDisposed();
                string path = Path.Combine(Workspace, "data", "loader-account-selection.json");
                if (!File.Exists(path)) return 0;
                try {
                    RequireOrdinaryDirectory(Path.GetDirectoryName(path)); RequireOrdinaryFile(path, 1024);
                    byte[] raw;
                    using (FileStream input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                        if (input.Length < 2 || input.Length > 1024) return 0;
                        raw = new byte[(int)input.Length]; int offset = 0, count;
                        while (offset < raw.Length && (count = input.Read(raw, offset, raw.Length - offset)) > 0) offset += count;
                        if (offset != raw.Length) return 0;
                    }
                    var value = new JavaScriptSerializer { MaxJsonLength = 1024, RecursionLimit = 4 }.DeserializeObject(new UTF8Encoding(false, true).GetString(raw)) as Dictionary<string, object>;
                    object version, selected;
                    if (value == null || value.Count != 2 || !value.TryGetValue("version", out version) || !(version is int) || (int)version != 1
                        || !value.TryGetValue("id", out selected) || !(selected is int || selected is long)) return 0;
                    long id = Convert.ToInt64(selected, CultureInfo.InvariantCulture);
                    foreach (AccountChoice account in accounts.Values) if (account.PlayerId == id) return id;
                } catch (IOException) { } catch (UnauthorizedAccessException) { } catch (ArgumentException) { } catch (InvalidOperationException) { }
                return 0;
            }
        }

        public void Start(AccountChoice account)
        {
            lock (sync)
            {
                ThrowIfDisposed();
                if (busy) throw new InvalidOperationException("Bir oyun oturumu zaten hazırlanıyor veya açık.");
                AccountChoice known;
                if (account == null || !accounts.TryGetValue(account.IdentityPath, out known) || !Object.ReferenceEquals(account, known))
                    throw new ArgumentException("Listeden geçerli bir hesap seçin.");
                AccountChoice current = ReadAccount(account.IdentityPath);
                if (!String.Equals(current.Digest, account.Digest, StringComparison.Ordinal))
                    throw new InvalidOperationException("Hesap dosyası değişti. Hesap listesini yenileyin.");
                RequireOrdinaryFile(Path.Combine(Workspace, "tools", "Zula-Start.ps1"), 1024 * 1024);
                RequireOrdinaryFile(Path.Combine(Workspace, "tools", "Zula-Launcher.ps1"), 1024 * 1024);
                busy = true; stopRequested = false; gameRunning = false;
                state = LauncherState.Starting; lastMessage = null;
                diagnostics = SessionDiagnostics.TryCreate(Workspace);
                LastDiagnosticLogPath = diagnostics == null ? null : diagnostics.Path;
                if (diagnostics != null) diagnostics.Write("session_start", "player_id", account.PlayerId.ToString(CultureInfo.InvariantCulture));
                operationDone.Reset();
            }
            Emit("Oyun dosyaları ve görseller kontrol ediliyor…");
            Thread worker = new Thread(delegate() { RunSession(account); });
            worker.Name = "Zula loader session";
            worker.IsBackground = true;
            try { worker.Start(); }
            catch
            {
                lock (sync)
                {
                    busy = false; state = LauncherState.Error;
                    if (diagnostics != null) { diagnostics.Write("worker_start_failed", null, null); diagnostics.Dispose(); diagnostics = null; }
                    operationDone.Set();
                }
                throw new InvalidOperationException("Oyun hazırlığı başlatılamadı.");
            }
        }

        public void Stop()
        {
            OwnedJob job;
            bool graceful;
            lock (sync)
            {
                if (!busy || stopRequested) return;
                stopRequested = true; state = LauncherState.Stopping;
                job = launchJob;
                graceful = gameRunning && launchStop != null;
                stopStarted = Stopwatch.GetTimestamp();
                if (graceful) launchStop.Set();
            }
            Emit("Oyun kapatılıyor, bağlantı ayarları geri alınıyor…");
                                                                            
                                                                                  
                                                                               
            if (!graceful && job != null) job.Dispose();
        }

        private void RunSession(AccountChoice account)
        {
            bool needsCleanup = false;
            bool reportedFailure = false;
            bool cleanupFailed = false;
            string friendlyError = null;
            int exitCode = 1;
            try
            {
                exitCode = RunPowerShell("Start", account.IdentityPath, true, 0, delegate(string line)
                {
                    if (String.IsNullOrEmpty(line)) return;
                    string failureCode = AuditOutput(line);
                    if (failureCode != null)
                    {
                                                                              
                                                                              
                                                                            
                        if (failureCode != "CLIENT_EXCEPTION") reportedFailure = true;
                        friendlyError = LastDiagnosticLogPath == null ? "Oyun başlatılırken bir hata oluştu." : "Oyun başlatılırken bir hata oluştu. Teknik kayıt kaydedildi.";
                        if (failureCode == "CLIENT_LAUNCH_END_UNCONFIRMED")
                        {
                            cleanupFailed = true;
                            friendlyError = "Oyun kapandı ancak sunucu oturumu temizlenemedi. Bağlantınızı kontrol edin.";
                        }
                    }
                    if (line.IndexOf("[hazir]", StringComparison.Ordinal) >= 0 || line.IndexOf("[hosts] Bes", StringComparison.Ordinal) >= 0 ||
                        line.IndexOf("Uzak istemci baslatiliyor", StringComparison.Ordinal) >= 0 || line.IndexOf("[SYS] zula PID=", StringComparison.Ordinal) >= 0)
                        needsCleanup = true;
                    if (line.IndexOf("[HATA]", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("[FATAL]", StringComparison.OrdinalIgnoreCase) >= 0)
                        friendlyError = ErrorCategory(line);
                    lock (sync) { if (stopRequested) return; }
                    if (line.IndexOf("Yalniz istemci:", StringComparison.Ordinal) >= 0) Emit("Sunucuya güvenli bağlantı doğrulanıyor…");
                    else if (line.IndexOf("[hazir]", StringComparison.Ordinal) >= 0) Emit("Sunucu hazır. Oyun bağlantısı hazırlanıyor…");
                    else if (line.IndexOf("[hosts] Bes", StringComparison.Ordinal) >= 0 || line.IndexOf("Uzak istemci baslatiliyor", StringComparison.Ordinal) >= 0) Emit("Oyun başlatılıyor…");
                    else if (line.IndexOf("[SYS] zula PID=", StringComparison.Ordinal) >= 0) Emit("Oyun yükleniyor…");
                    else if (line.IndexOf("[SYS] resume", StringComparison.Ordinal) >= 0)
                    {
                        lock (sync) { if (stopRequested) return; state = LauncherState.Running; gameRunning = true; }
                        Emit("Oyun açık.");
                    }
                    else if (line.IndexOf("[SYS] oyun oturumu ayrildi:", StringComparison.Ordinal) >= 0) Emit("Oyun kapandı. Bağlantı ayarları geri alınıyor…");
                });
                if (reportedFailure && exitCode == 0) exitCode = 1;
            }
            catch (Exception exception)
            {
                Audit("bridge_exception", "type", SafeExceptionType(exception.GetType().Name));
                friendlyError = "Oyun başlatıcısı çalıştırılamadı. Kurulum dosyalarını kontrol edin.";
            }
            finally
            {
                lock (sync) { gameRunning = false; state = LauncherState.Stopping; }
                                                                               
                                                                             
                if (needsCleanup)
                {
                    Emit("Bağlantı ayarları geri alınıyor…");
                    try
                    {
                        if (RunPowerShell("StopClient", null, false, 30000, null) != 0)
                        { cleanupFailed = true; exitCode = 1; friendlyError = "Oyun kapatıldı ancak bağlantı ayarları geri alınamadı. Başlatıcıyı yeniden açıp tekrar deneyin."; }
                    }
                    catch { cleanupFailed = true; exitCode = 1; friendlyError = "Bağlantı temizliği tamamlanamadı. Başlatıcıyı yeniden açıp tekrar deneyin."; }
                }
                bool wasStopped;
                lock (sync)
                {
                    wasStopped = stopRequested;
                    if (wasStopped && !cleanupFailed) exitCode = 0;
                    busy = false; launchJob = null;
                    state = exitCode == 0 ? LauncherState.Idle : LauncherState.Error;
                    if (diagnostics != null)
                    {
                        diagnostics.Write("session_exit", "exit_code", exitCode.ToString(CultureInfo.InvariantCulture));
                        diagnostics.Dispose(); diagnostics = null;
                    }
                    operationDone.Set();
                }
                Emit(exitCode == 0 ? (wasStopped ? "Oyun kapatıldı." : "Oyun kapandı.") :
                    (friendlyError ?? "Oyun açılamadı veya beklenmedik şekilde kapandı. Tekrar deneyin. (" + exitCode.ToString(CultureInfo.InvariantCulture) + ")"));
                Action<int> completed = Completed;
                if (completed != null) { try { completed(exitCode); } catch { } }
            }
        }

        private int RunPowerShell(string action, string identity, bool session, int timeoutMs, Action<string> onLine)
        {
            string script = Path.Combine(Workspace, "tools", action == "Start" ? "Zula-Start.ps1" : "Zula-Launcher.ps1");
            RequireOrdinaryFile(script, 1024 * 1024);
            string gateName = @"Local\ZulaLoader-" + Guid.NewGuid().ToString("N");
            string stopName = @"Local\ZulaLoader-Stop-" + Guid.NewGuid().ToString("N");
            EventWaitHandleSecurity security = new EventWaitHandleSecurity();
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new EventWaitHandleAccessRule(user, EventWaitHandleRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new EventWaitHandleAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), EventWaitHandleRights.FullControl, AccessControlType.Allow));
            bool created;
            bool stopCreated;
            using (EventWaitHandle gate = new EventWaitHandle(false, EventResetMode.ManualReset, gateName, out created, security))
            using (EventWaitHandle stop = new EventWaitHandle(false, EventResetMode.ManualReset, stopName, out stopCreated, security))
            using (OwnedJob job = new OwnedJob())
            using (Process process = new Process())
            {
                if (!created || !stopCreated) throw new InvalidOperationException("Başlatma oturumu oluşturulamadı.");
                Dictionary<string, object> payload = new Dictionary<string, object>();
                payload.Add("gate", gateName); payload.Add("script", script); payload.Add("workspace", Workspace);
                payload.Add("action", action); payload.Add("server", DefaultServer); payload.Add("identity", identity);
                string data = Convert.ToBase64String(Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(payload)));
                                                                             
                                                                                 
                string command = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); $OutputEncoding=[Console]::OutputEncoding; " +
                    "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data + "')) | ConvertFrom-Json; " +
                    "$g=[Threading.EventWaitHandle]::OpenExisting($p.gate); try { if(-not $g.WaitOne(15000)){exit 126} } finally {$g.Dispose()}; " +
                    "if($p.action -ceq 'Start'){ & $p.script --server $p.server --identity $p.identity } " +
                    "elseif($p.action -ceq 'StopClient'){ & $p.script -Action StopClient -Workspace $p.workspace } else {exit 125}; exit $LASTEXITCODE";
                process.StartInfo = new ProcessStartInfo {
                    FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"),
                    Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(command)),
                    WorkingDirectory = Workspace, UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
                };
                process.StartInfo.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
                process.StartInfo.EnvironmentVariables["PYTHONUNBUFFERED"] = "1";
                                                                             
                                                                                  
                process.StartInfo.EnvironmentVariables.Remove("ZULA_GAME_HOST");
                if (session) process.StartInfo.EnvironmentVariables["ZULA_LAUNCHER_STOP_EVENT"] = stopName;
                else process.StartInfo.EnvironmentVariables.Remove("ZULA_LAUNCHER_STOP_EVENT");
                DataReceivedEventHandler handler = delegate(object sender, DataReceivedEventArgs args)
                {
                    if (args.Data != null && onLine != null)
                    {
                        foreach (string line in DecodeOutputLines(args.Data)) { try { onLine(line); } catch { } }
                    }
                };
                process.OutputDataReceived += handler; process.ErrorDataReceived += handler;
                bool processStarted = false;
                try
                {
                    lock (sync)
                    {
                        if (session && stopRequested) return 0;
                        if (!process.Start()) throw new InvalidOperationException("Başlatıcı oluşturulamadı.");
                        processStarted = true;
                        job.Assign(process);
                        if (session) { launchJob = job; launchStop = stop; }
                    }
                    process.BeginOutputReadLine(); process.BeginErrorReadLine();
                    gate.Set();
                    if (timeoutMs > 0 && !process.WaitForExit(timeoutMs))
                    {
                        job.Dispose(); process.WaitForExit(5000);
                        throw new TimeoutException("Bağlantı temizliği zaman aşımına uğradı.");
                    }
                    if (timeoutMs == 0)
                    {
                                                                           
                                                                             
                                                                        
                        while (!process.WaitForExit(250))
                        {
                            bool expired;
                            lock (sync) { expired = stopRequested && (Stopwatch.GetTimestamp() - stopStarted) / (double)Stopwatch.Frequency >= 15; }
                            if (expired)
                            {
                                Audit("stop_timeout", null, null); job.Dispose();
                                if (!process.WaitForExit(5000))
                                {
                                    process.Kill();
                                    if (!process.WaitForExit(5000)) throw new TimeoutException("Oyun kapatma zaman aşımına uğradı.");
                                }
                                break;
                            }
                        }
                    }
                    job.Dispose();
                    process.WaitForExit();                                          
                    Audit(session ? "launcher_exit" : "cleanup_exit", "exit_code", process.ExitCode.ToString(CultureInfo.InvariantCulture));
                    return process.ExitCode;
                }
                finally
                {
                    job.Dispose();
                    if (processStarted)
                    {
                        try { if (!process.HasExited) { process.Kill(); process.WaitForExit(5000); } } catch { }
                    }
                    lock (sync) { if (session && Object.ReferenceEquals(launchJob, job)) { launchJob = null; launchStop = null; } }
                }
            }
        }

        private static AccountChoice ReadAccount(string path)
        {
            string ignored;
            return ReadAccount(path, out ignored);
        }

        private static AccountChoice ReadAccount(string path, out string password)
        {
            password = null;
            RequireOrdinaryFile(path, 65536);
            byte[] bytes;
            using (FileStream input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (input.Length < 2 || input.Length > 65536) throw new ArgumentException("Geçersiz hesap dosyası.");
                bytes = new byte[(int)input.Length]; int offset = 0, count;
                while (offset < bytes.Length && (count = input.Read(bytes, offset, bytes.Length - offset)) > 0) offset += count;
                if (offset != bytes.Length) throw new IOException("Hesap dosyası okunamadı.");
            }
            int prefix = bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf ? 3 : 0;
            string json = new UTF8Encoding(false, true).GetString(bytes, prefix, bytes.Length - prefix);
            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 8 };
            Dictionary<string, object> obj = serializer.DeserializeObject(json) as Dictionary<string, object>;
            object id, name, token;
            if (obj == null || !obj.TryGetValue("Id", out id) || !obj.TryGetValue("NickName", out name) || !obj.TryGetValue("Token", out token) ||
                !(id is int || id is long) || !(name is string) || !(token is string)) throw new ArgumentException("Geçersiz hesap dosyası.");
            long playerId = Convert.ToInt64(id, CultureInfo.InvariantCulture);
            string nickname = (string)name, ticket = (string)token;
            if (playerId < 1 || playerId > Int32.MaxValue || String.IsNullOrWhiteSpace(nickname) || nickname.Length > 64 ||
                Regex.IsMatch(nickname, @"[\p{C}\r\n]") || !Regex.IsMatch(ticket, @"\A[\x21-\x7e]{32,128}\z"))
                throw new ArgumentException("Geçersiz hesap dosyası.");
            string digest;
            using (SHA256 sha = SHA256.Create()) { digest = Convert.ToBase64String(sha.ComputeHash(bytes)); }
            password = ticket;
            return new AccountChoice(playerId, nickname.Trim(), Path.GetFullPath(path), digest);
        }

        private static void RequireOrdinaryFile(string path, long maxBytes)
        {
            FileInfo file = new FileInfo(path);
            if (!file.Exists || (file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 || file.Length > maxBytes)
                throw new ArgumentException("Gerekli kurulum dosyası eksik veya geçersiz.");
        }
        private static void RequireOrdinaryDirectory(string path)
        {
            DirectoryInfo directory = new DirectoryInfo(path);
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Kurulum klasörü eksik veya geçersiz.");
        }
        private static string ErrorCategory(string line)
        {
            if (line.IndexOf("gorsel", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("dokusu", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Oyun görselleri doğrulanamadı. Oyun dosyalarını kontrol edin.";
            if (line.IndexOf("frida yok", StringComparison.OrdinalIgnoreCase) >= 0) return "Frida bileşeni eksik. Python kurulumunu kontrol edin.";
            if (line.IndexOf("sunucu", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("TLS", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("sertifika", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Sunucu bağlantısı doğrulanamadı. Bağlantıyı kontrol edip tekrar deneyin.";
            if (line.IndexOf("hosts", StringComparison.OrdinalIgnoreCase) >= 0) return "Oyun bağlantı ayarları hazırlanamadı. Yönetici iznini ve hosts dosyasını kontrol edin.";
            if (line.IndexOf("zula.exe", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("Oyun dosyasi yok", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Zula oyun dosyası bulunamadı. Oyun kurulumunu kontrol edin.";
            return "Oyun başlatılamadı. Başlatıcı bileşenlerini kontrol edip tekrar deneyin.";
        }
        private void Emit(string message)
        {
            LauncherState current;
            lock (sync)
            {
                if (lastMessage == message) return; lastMessage = message; current = state;
                if (diagnostics != null) diagnostics.Write("status", "message", message);
            }
            Action<string> text = Status;
            if (text != null) { try { text(message); } catch { } }
            Action<LauncherState, string> change = StatusChanged;
            if (change != null) { try { change(current, message); } catch { } }
        }
        private void Audit(string name, string key, string value)
        {
            lock (sync) { if (diagnostics != null) diagnostics.Write(name, key, value); }
        }
        private string AuditOutput(string line)
        {
                                                                           
                                                                            
            string code = null;
            Match launchEnd = Regex.Match(line, @"\A\s*\[CLIENT-LAUNCH\]\s+(ENDED|END_UNCONFIRMED)\s*\z");
            if (launchEnd.Success)
            {
                Audit("launch_end", "state", launchEnd.Groups[1].Value);
                if (launchEnd.Groups[1].Value == "END_UNCONFIRMED") code = "CLIENT_LAUNCH_END_UNCONFIRMED";
            }
            Match nativeExit = Regex.Match(line, @"\A\s*\[CLIENT-EXIT\]\s+code=(0x[0-9A-Fa-f]{8})\s*\z");
            if (nativeExit.Success)
            {
                string nativeCode = nativeExit.Groups[1].Value.ToLowerInvariant();
                Audit("native_exit", "code", nativeCode);
                if (nativeCode != "0x00000000") code = "CLIENT_NATIVE_EXIT";
            }
            Match exitObserver = Regex.Match(line, @"\A\s*\[CLIENT-EXIT\]\s+(OBSERVER_UNAVAILABLE|STATUS_UNAVAILABLE|OBSERVER_CLOSE_FAILED)\s*\z");
            if (exitObserver.Success) Audit("exit_observer", "state", exitObserver.Groups[1].Value);
            Match pin = Regex.Match(line, @"\A\s*\[TLS-PIN\]\s+(INSTALL_FAILED|CURL_PIN_FAILED|CURL_PATH_MISMATCH|MULTIPLE_CURL_MODULES|CURL_MODULE_REMOVED|SETOPT_FAILED|SETOPT_REJECT|INSTALLED)\b");
            if (pin.Success)
            {
                string pinState = pin.Groups[1].Value;
                Audit("tls_pin", "state", pinState);
                if (pinState != "INSTALLED") code = "TLS_PIN_" + pinState;
            }
            if (line.IndexOf("invalid abi", StringComparison.OrdinalIgnoreCase) >= 0) code = "NATIVE_ABI_INVALID";
            else if (line.IndexOf("Remote TLS enforcement was not armed", StringComparison.Ordinal) >= 0) code = "REMOTE_TLS_NOT_ARMED";
            else if (line.IndexOf("Failed to spawn", StringComparison.OrdinalIgnoreCase) >= 0) code = "CLIENT_SPAWN_FAILED";
            else if (line.IndexOf("[CRASH]", StringComparison.Ordinal) >= 0) code = "CLIENT_CRASH_REPORTED";
            else if (line.IndexOf("[frida-err]", StringComparison.Ordinal) >= 0) code = "FRIDA_CALLBACK_ERROR";
            Match exception = Regex.Match(line, @"(?:\A|[\s:])(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception)|Error|Exception):");
            if (exception.Success)
            {
                string type = SafeExceptionType(exception.Groups[1].Value);
                Audit("client_exception", "type", type);
                if (code == null && type != "Exception") code = "CLIENT_EXCEPTION";
            }
            Match frame = Regex.Match(line, "\\bFile \\\"([^\\\"]+)\\\", line ([0-9]{1,7})");
            if (frame.Success)
            {
                string file = System.IO.Path.GetFileName(frame.Groups[1].Value);
                if (Regex.IsMatch(file, @"\A[A-Za-z_][A-Za-z0-9_.-]{0,79}\.(?:py|ps1|js)\z") && !Regex.IsMatch(file, @"[A-Fa-f0-9]{24,}"))
                    Audit("client_frame", "source", file + ":" + frame.Groups[2].Value);
            }
            if (line.IndexOf("[SYS] oyun oturumu ayrildi:", StringComparison.Ordinal) >= 0)
            {
                string[] reasons = { "process-terminated", "process-replaced", "connection-terminated", "device-lost", "application-requested" };
                string reason = "unknown";
                foreach (string candidate in reasons) { if (line.IndexOf(candidate, StringComparison.Ordinal) >= 0) { reason = candidate; break; } }
                Audit("client_detached", "reason", reason);
            }
            if (code != null) Audit("client_failure", "code", code);
            return code;
        }
        private static string SafeExceptionType(string value)
        {
            string[] allowed = { "ArgumentException", "ArgumentNullException", "InvalidOperationException", "Win32Exception", "IOException", "UnauthorizedAccessException", "TimeoutException", "TypeError", "ValueError", "RuntimeError", "OSError", "IOError", "FileNotFoundError", "PermissionError", "ModuleNotFoundError", "ImportError", "RPCException", "InvalidOperationError", "ProcessNotFoundError", "PermissionDeniedError", "TransportError", "ServerNotRunningError", "NotSupportedError", "Error" };
            foreach (string type in allowed) { if (String.Equals(type, value, StringComparison.Ordinal)) return type; }
            return "Exception";
        }
        private static IEnumerable<string> DecodeOutputLines(string value)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 65536 || value == "#< CLIXML") return new string[0];
            if (!value.TrimStart().StartsWith("<Objs", StringComparison.Ordinal)) return new string[] { value };
                                                                            
                                                                                 
            List<string> lines = new List<string>();
            try
            {
                XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 65536 };
                XmlDocument document = new XmlDocument { XmlResolver = null };
                using (StringReader input = new StringReader(value))
                using (XmlReader reader = XmlReader.Create(input, settings)) { document.Load(reader); }
                foreach (XmlNode node in document.GetElementsByTagName("S"))
                {
                    XmlAttribute stream = node.Attributes["S"], name = node.Attributes["N"];
                    if ((stream != null && String.Equals(stream.Value, "Error", StringComparison.OrdinalIgnoreCase)) || (name != null && name.Value == "Message"))
                    {
                        string decoded = Regex.Replace(node.InnerText, @"_x([A-Fa-f0-9]{4})_", delegate(Match match) { return ((char)Int32.Parse(match.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToString(); });
                        lines.AddRange(decoded.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries));
                    }
                }
            }
            catch { }
            return lines;
        }

        private sealed class SessionDiagnostics : IDisposable
        {
            private StreamWriter writer;
            private int records, bytes;
            public string Path { get; private set; }
            public static SessionDiagnostics TryCreate(string workspace)
            {
                try
                {
                    string logs = System.IO.Path.Combine(workspace, "logs");
                    Directory.CreateDirectory(logs); RequireOrdinaryDirectory(logs);
                    string directory = System.IO.Path.Combine(logs, "loader");
                    Directory.CreateDirectory(directory); RequireOrdinaryDirectory(directory);
                    string path = System.IO.Path.Combine(directory, "session-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N") + ".jsonl");
                    FileSecurity security = new FileSecurity(); security.SetAccessRuleProtection(true, false);
                    security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
                    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
                    FileStream stream = new FileStream(path, FileMode.CreateNew, FileSystemRights.Write, FileShare.Read, 4096, FileOptions.None, security);
                    return new SessionDiagnostics { Path = path, writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true } };
                }
                catch { return null; }
            }
            public void Write(string name, string key, string value)
            {
                if (writer == null || records >= 512 || bytes >= 131072) return;
                try
                {
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item.Add("utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)); item.Add("event", name);
                    if (key != null) item.Add(key, value);
                    string line = new JavaScriptSerializer().Serialize(item);
                    int length = Encoding.UTF8.GetByteCount(line) + 2;
                    if (bytes + length > 131072) return;
                    writer.WriteLine(line); records++; bytes += length;
                }
                catch { Dispose(); }
            }
            public void Dispose() { if (writer != null) { try { writer.Dispose(); } catch { } writer = null; } }
        }
        private void ThrowIfDisposed() { if (disposed) throw new ObjectDisposedException("LauncherBridge"); }
        public void Dispose()
        {
            lock (sync) { if (disposed) return; disposed = true; }
            Stop();
                                                                           
                                                                                
            operationDone.WaitOne(50000);
                                                                                 
        }

        private sealed class OwnedJob : IDisposable
        {
            private readonly object jobSync = new object();
            private IntPtr handle;
            public OwnedJob()
            {
                handle = CreateJobObject(IntPtr.Zero, null);
                if (handle == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION value = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                value.BasicLimitInformation.LimitFlags = 0x00002000;                     
                int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr memory = Marshal.AllocHGlobal(length);
                try
                {
                    Marshal.StructureToPtr(value, memory, false);
                    if (!SetInformationJobObject(handle, 9, memory, (uint)length)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
                catch { Dispose(); throw; }
                finally { Marshal.FreeHGlobal(memory); }
            }
            public void Assign(Process process)
            {
                lock (jobSync)
                {
                    if (handle == IntPtr.Zero) throw new ObjectDisposedException("OwnedJob");
                    if (!AssignProcessToJobObject(handle, process.Handle)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            public void Dispose()
            {
                lock (jobSync)
                {
                    if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
                }
            }
            [StructLayout(LayoutKind.Sequential)] private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
                public uint LimitFlags;
                public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
                public uint ActiveProcessLimit;
                public UIntPtr Affinity;
                public uint PriorityClass, SchedulingClass;
            }
            [StructLayout(LayoutKind.Sequential)] private struct IO_COUNTERS
            {
                public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
            }
            [StructLayout(LayoutKind.Sequential)] private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
                public IO_COUNTERS IoInfo;
                public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
            [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        }
    }
}
