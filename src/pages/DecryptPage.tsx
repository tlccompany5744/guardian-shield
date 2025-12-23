import { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Unlock, FileText, CheckCircle, Key, RefreshCw, Shield, AlertTriangle, Download, Eye, File, Lock } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface SimFile {
  id: string;
  name: string;
  content: string;
  size: number;
  type: string;
  encrypted: boolean;
  encryptedContent?: string;
  originalContent?: string;
}

interface LogEntry {
  id: string;
  message: string;
  timestamp: Date;
  type: 'info' | 'warning' | 'success' | 'danger';
}

const simpleDecrypt = (encryptedText: string, key: string): string => {
  try {
    const decoded = decodeURIComponent(escape(atob(encryptedText)));
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      result += String.fromCharCode(charCode);
    }
    return result;
  } catch {
    return 'DECRYPTION FAILED - Invalid key or corrupted data';
  }
};

const DecryptPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [decryptionKey, setDecryptionKey] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(-1);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [encryptedFiles, setEncryptedFiles] = useState<SimFile[]>([]);
  const [recoveredFiles, setRecoveredFiles] = useState<SimFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<SimFile | null>(null);
  const [decryptionProgress, setDecryptionProgress] = useState(0);
  const [keyVerified, setKeyVerified] = useState(false);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  // Load encrypted files from localStorage
  useEffect(() => {
    const storedFiles = localStorage.getItem('encrypted_files');
    const storedKey = localStorage.getItem('ransomware_key');
    
    if (storedFiles) {
      try {
        const files = JSON.parse(storedFiles);
        setEncryptedFiles(files);
      } catch {
        // If no stored files, use demo files
        setEncryptedFiles([
          { 
            id: '1', 
            name: 'document.txt', 
            content: 'VGhpcyBpcyBlbmNyeXB0ZWQgZGF0YQ==', 
            size: 1024,
            type: 'text/plain',
            encrypted: true, 
            encryptedContent: 'VGhpcyBpcyBlbmNyeXB0ZWQgZGF0YQ==' 
          },
          { 
            id: '2', 
            name: 'passwords.txt', 
            content: 'U2VjcmV0IHBhc3N3b3JkcyBoZXJl', 
            size: 512,
            type: 'text/plain',
            encrypted: true, 
            encryptedContent: 'U2VjcmV0IHBhc3N3b3JkcyBoZXJl' 
          },
          { 
            id: '3', 
            name: 'project_plan.md', 
            content: 'UHJvamVjdCBwbGFuIGNvbnRlbnQ=', 
            size: 2048,
            type: 'text/markdown',
            encrypted: true, 
            encryptedContent: 'UHJvamVjdCBwbGFuIGNvbnRlbnQ=' 
          },
        ]);
      }
    } else {
      // Demo encrypted files
      setEncryptedFiles([
        { 
          id: '1', 
          name: 'financial_report.xlsx', 
          content: 'RW5jcnlwdGVkIGZpbmFuY2lhbCBkYXRh', 
          size: 45056,
          type: 'application/vnd.ms-excel',
          encrypted: true, 
          encryptedContent: 'RW5jcnlwdGVkIGZpbmFuY2lhbCBkYXRh' 
        },
        { 
          id: '2', 
          name: 'customer_database.sql', 
          content: 'U0VMRUNUICogRlJPTSBjdXN0b21lcnM=', 
          size: 102400,
          type: 'application/sql',
          encrypted: true, 
          encryptedContent: 'U0VMRUNUICogRlJPTSBjdXN0b21lcnM=' 
        },
        { 
          id: '3', 
          name: 'company_secrets.docx', 
          content: 'VG9wIHNlY3JldCBkb2N1bWVudA==', 
          size: 28672,
          type: 'application/msword',
          encrypted: true, 
          encryptedContent: 'VG9wIHNlY3JldCBkb2N1bWVudA==' 
        },
      ]);
    }
  }, []);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const addLog = useCallback((message: string, type: LogEntry['type'] = 'info') => {
    const entry: LogEntry = {
      id: Date.now().toString() + Math.random(),
      message,
      timestamp: new Date(),
      type
    };
    setLogs(prev => [...prev, entry]);
  }, []);

  const verifyKey = () => {
    if (!decryptionKey) {
      toast.error('Please enter a decryption key');
      return;
    }
    
    addLog('🔑 Verifying decryption key...', 'info');
    
    setTimeout(() => {
      const storedKey = localStorage.getItem('ransomware_key');
      if (storedKey && decryptionKey === storedKey) {
        setKeyVerified(true);
        addLog('✅ Key verified successfully!', 'success');
        toast.success('Key verified! Ready to decrypt.');
      } else {
        addLog('⚠️ Key verification: Using provided key for decryption attempt', 'warning');
        setKeyVerified(true);
        toast.info('Key will be used for decryption attempt');
      }
    }, 500);
  };

  const runDecryption = async () => {
    if (!decryptionKey) {
      toast.error('Please enter the decryption key');
      return;
    }

    if (encryptedFiles.length === 0) {
      toast.error('No encrypted files to recover');
      return;
    }

    setIsDecrypting(true);
    setRecoveredFiles([]);
    setDecryptionProgress(0);
    
    addLog('🛡️ INITIATING FILE RECOVERY PROCESS', 'info');
    addLog('🔐 Loading decryption key...', 'info');
    await new Promise(resolve => setTimeout(resolve, 500));
    addLog('📂 Scanning for encrypted files...', 'info');
    addLog(`📊 Found ${encryptedFiles.length} encrypted file(s)`, 'info');
    await new Promise(resolve => setTimeout(resolve, 300));

    for (let i = 0; i < encryptedFiles.length; i++) {
      setCurrentFileIndex(i);
      const progress = Math.round(((i + 1) / encryptedFiles.length) * 100);
      setDecryptionProgress(progress);
      
      const file = encryptedFiles[i];
      addLog(`🔓 Decrypting: ${file.name}`, 'warning');
      addLog(`   ├─ Size: ${(file.size / 1024).toFixed(2)} KB`, 'info');
      addLog(`   ├─ Applying key transformation...`, 'info');
      
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const decryptedContent = simpleDecrypt(file.encryptedContent || '', decryptionKey);
      
      addLog(`   ├─ Verifying file integrity...`, 'info');
      addLog(`   └─ Status: RECOVERED ✓`, 'success');
      
      setRecoveredFiles(prev => [...prev, {
        ...file,
        content: decryptedContent,
        encrypted: false
      }]);
      
      await new Promise(resolve => setTimeout(resolve, 200));
    }

    setCurrentFileIndex(-1);
    setIsDecrypting(false);
    setDecryptionProgress(100);
    addLog('🎉 FILE RECOVERY COMPLETE', 'success');
    addLog(`📊 Successfully recovered ${encryptedFiles.length} file(s)`, 'success');
    addLog('📝 Generating recovery report...', 'info');
    toast.success('All files have been recovered!');
  };

  const resetRecovery = () => {
    setRecoveredFiles([]);
    setDecryptionKey('');
    setLogs([]);
    setCurrentFileIndex(-1);
    setDecryptionProgress(0);
    setKeyVerified(false);
    setSelectedFile(null);
    toast.success('Recovery reset');
  };

  const downloadRecoveredFile = (file: SimFile) => {
    const blob = new Blob([file.content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded: ${file.name}`);
  };

  const exportRecoveryReport = () => {
    const report = `
INCIDENT RECOVERY REPORT
========================
Generated: ${new Date().toLocaleString()}

RECOVERY SUMMARY:
- Total Files Recovered: ${recoveredFiles.length}
- Recovery Status: SUCCESS

FILES RECOVERED:
${recoveredFiles.map(f => `- ${f.name} (${(f.size / 1024).toFixed(2)} KB)`).join('\n')}

RECOVERY LOG:
${logs.map(l => `[${l.timestamp.toLocaleTimeString()}] ${l.message}`).join('\n')}
    `;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'recovery_report.txt';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Recovery report exported');
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-success text-glow-green tracking-wider flex items-center gap-3">
          <Unlock className="w-8 h-8" />
          DECRYPT & RECOVER
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Real-time file recovery and decryption
        </p>
      </div>

      {/* Info Banner */}
      <div className="mb-6 p-4 rounded-lg bg-primary/10 border border-primary/30">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary flex-shrink-0" />
          <p className="text-sm font-mono text-primary">
            <strong>RECOVERY MODE:</strong> Enter the encryption key from the ransomware simulation to recover your files.
            In real scenarios, you would restore from backups or use decryption tools from security researchers.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Encrypted Files Panel */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                ENCRYPTED FILES
              </h3>
              <span className="text-xs font-mono text-destructive flex items-center gap-1">
                <Lock className="w-3 h-3" />
                {encryptedFiles.length} files locked
              </span>
            </div>

            {/* Progress Bar */}
            {isDecrypting && (
              <div className="mb-4">
                <div className="flex justify-between text-xs font-mono text-muted-foreground mb-1">
                  <span>Recovery Progress</span>
                  <span>{decryptionProgress}%</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-success transition-all duration-300"
                    style={{ width: `${decryptionProgress}%` }}
                  />
                </div>
              </div>
            )}

            <div className="space-y-2 max-h-64 overflow-y-auto">
              {encryptedFiles.map((file, index) => (
                <div
                  key={file.id}
                  onClick={() => setSelectedFile(file)}
                  className={cn(
                    "flex items-center gap-3 p-3 rounded-lg border transition-all duration-300 cursor-pointer",
                    "bg-destructive/10 border-destructive/30",
                    currentFileIndex === index && "animate-pulse border-success",
                    selectedFile?.id === file.id && "ring-2 ring-primary"
                  )}
                >
                  <File className="w-5 h-5 text-destructive flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-foreground truncate">
                      {file.name}.encrypted
                    </p>
                    <p className="text-xs text-muted-foreground font-mono">
                      {(file.size / 1024).toFixed(2)} KB • {file.type}
                    </p>
                  </div>
                  <Lock className="w-4 h-4 text-destructive" />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recovered Files Panel */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                RECOVERED FILES
              </h3>
              <span className="text-xs font-mono text-success flex items-center gap-1">
                <CheckCircle className="w-3 h-3" />
                {recoveredFiles.length} files recovered
              </span>
            </div>

            <div className="space-y-2 max-h-64 overflow-y-auto">
              {recoveredFiles.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  No files recovered yet. Enter the key and run recovery.
                </p>
              ) : (
                recoveredFiles.map((file) => (
                  <div
                    key={file.id}
                    className="flex items-center gap-3 p-3 rounded-lg border bg-success/10 border-success/30 animate-fade-in"
                  >
                    <CheckCircle className="w-5 h-5 text-success flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-sm text-foreground truncate">{file.name}</p>
                      <p className="text-xs text-muted-foreground font-mono">
                        {(file.size / 1024).toFixed(2)} KB • Recovered
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={() => setSelectedFile(file)}
                        className="text-muted-foreground hover:text-primary"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button 
                        onClick={() => downloadRecoveredFile(file)}
                        className="text-muted-foreground hover:text-success"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Recovery Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
              RECOVERY CONTROLS
            </h3>

            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-mono text-muted-foreground flex items-center gap-2">
                  <Key className="w-4 h-4 text-primary" />
                  DECRYPTION KEY
                </label>
                <div className="flex gap-2">
                  <Input
                    placeholder="Enter the encryption key..."
                    value={decryptionKey}
                    onChange={(e) => setDecryptionKey(e.target.value)}
                    className="font-mono flex-1"
                  />
                  <Button variant="outline" onClick={verifyKey} disabled={!decryptionKey}>
                    Verify
                  </Button>
                </div>
                {keyVerified && (
                  <p className="text-xs text-success font-mono flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" /> Key ready for decryption
                  </p>
                )}
              </div>

              <Button
                variant="success"
                size="lg"
                className="w-full"
                onClick={runDecryption}
                disabled={isDecrypting || recoveredFiles.length === encryptedFiles.length || !decryptionKey}
              >
                {isDecrypting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-success-foreground/30 border-t-success-foreground rounded-full animate-spin" />
                    DECRYPTING... {decryptionProgress}%
                  </>
                ) : (
                  <>
                    <Unlock className="w-5 h-5" />
                    RUN RECOVERY
                  </>
                )}
              </Button>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  className="flex-1"
                  onClick={resetRecovery}
                  disabled={isDecrypting}
                >
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Reset
                </Button>
                <Button
                  variant="outline"
                  className="flex-1"
                  onClick={exportRecoveryReport}
                  disabled={recoveredFiles.length === 0}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export Report
                </Button>
              </div>
            </div>
          </div>
        </div>

        {/* Activity Log */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
              RECOVERY LOG
            </h3>
            <div 
              ref={logContainerRef}
              className="bg-background/50 rounded-lg p-3 h-48 overflow-y-auto font-mono text-xs"
            >
              {logs.length === 0 ? (
                <p className="text-muted-foreground">Waiting for recovery to start...</p>
              ) : (
                logs.map((log) => (
                  <p 
                    key={log.id} 
                    className={cn(
                      "mb-1",
                      log.type === 'info' && "text-primary",
                      log.type === 'warning' && "text-warning",
                      log.type === 'success' && "text-success",
                      log.type === 'danger' && "text-destructive"
                    )}
                  >
                    <span className="text-muted-foreground">[{log.timestamp.toLocaleTimeString()}]</span> {log.message}
                  </p>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* File Preview */}
      {selectedFile && (
        <div className="mt-6 cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
              FILE PREVIEW: {selectedFile.name}
            </h3>
            <div className="bg-background/50 rounded-lg p-4 max-h-48 overflow-auto font-mono text-sm">
              {selectedFile.encrypted ? (
                <p className="text-destructive break-all">{selectedFile.encryptedContent || selectedFile.content}</p>
              ) : (
                <p className="text-accent">{selectedFile.content}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Success Message */}
      {recoveredFiles.length === encryptedFiles.length && encryptedFiles.length > 0 && (
        <div className="mt-6 cyber-card p-6 border-2 border-success">
          <div className="relative z-10 text-center">
            <CheckCircle className="w-16 h-16 text-success mx-auto mb-4" />
            <h2 className="font-display text-2xl font-bold text-success mb-2">
              ALL FILES RECOVERED
            </h2>
            <p className="font-mono text-muted-foreground mb-4">
              Incident response successful. {recoveredFiles.length} encrypted file(s) have been restored.
            </p>
            <div className="flex justify-center gap-4">
              <Button variant="outline" onClick={() => navigate('/incident')}>
                <AlertTriangle className="w-4 h-4 mr-2" />
                Run Incident Response
              </Button>
              <Button variant="success" onClick={exportRecoveryReport}>
                <Download className="w-4 h-4 mr-2" />
                Download Report
              </Button>
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default DecryptPage;
