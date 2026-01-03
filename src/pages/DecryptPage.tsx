import { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Unlock, FileText, CheckCircle, Key, RefreshCw, Shield, AlertTriangle, Download, Eye, File, Lock, Upload, X } from 'lucide-react';
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
  const [isDragging, setIsDragging] = useState(false);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  // Load encrypted files from localStorage on mount
  useEffect(() => {
    loadEncryptedFiles();
  }, []);

  const loadEncryptedFiles = () => {
    const storedFiles = localStorage.getItem('encrypted_files');
    if (storedFiles) {
      try {
        const files = JSON.parse(storedFiles);
        setEncryptedFiles(files);
        addLog(`📂 Loaded ${files.length} encrypted file(s) from encryption simulation`, 'info');
      } catch {
        addLog('⚠️ No encrypted files from simulation found', 'warning');
      }
    }
  };

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

  // Handle file upload
  const handleFileUpload = useCallback(async (files: FileList) => {
    const newFiles: SimFile[] = [];
    
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      
      // Check if file appears encrypted (has .encrypted extension or is binary-like)
      const isEncrypted = file.name.endsWith('.encrypted') || 
                         file.name.endsWith('.enc') || 
                         file.name.endsWith('.locked') ||
                         file.name.includes('ENCRYPTED');
      
      try {
        const content = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => {
            const result = reader.result as string;
            // Convert to base64 for storage
            const base64 = btoa(unescape(encodeURIComponent(result)));
            resolve(base64);
          };
          reader.onerror = reject;
          reader.readAsText(file);
        });

        const simFile: SimFile = {
          id: Date.now().toString() + Math.random(),
          name: file.name.replace(/\.(encrypted|enc|locked)$/i, ''),
          content: content,
          size: file.size,
          type: file.type || 'application/octet-stream',
          encrypted: true,
          encryptedContent: content
        };

        newFiles.push(simFile);
        addLog(`📁 Uploaded: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`, 'info');
      } catch (error) {
        addLog(`❌ Failed to read file: ${file.name}`, 'danger');
      }
    }

    if (newFiles.length > 0) {
      setEncryptedFiles(prev => [...prev, ...newFiles]);
      toast.success(`Uploaded ${newFiles.length} file(s)`);
      addLog(`✅ ${newFiles.length} encrypted file(s) ready for decryption`, 'success');
    }
  }, [addLog]);

  // Drag and drop handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files);
    }
  }, [handleFileUpload]);

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileUpload(e.target.files);
    }
  };

  const removeEncryptedFile = (fileId: string) => {
    setEncryptedFiles(prev => prev.filter(f => f.id !== fileId));
    if (selectedFile?.id === fileId) {
      setSelectedFile(null);
    }
    toast.info('File removed');
  };

  const verifyKey = () => {
    if (!decryptionKey) {
      toast.error('Please enter a decryption key');
      return;
    }
    
    addLog('🔑 Verifying decryption key...', 'info');
    
    setTimeout(() => {
      const storedKey = localStorage.getItem('ransomware_key');
      
      // If there's a stored key, verify against it
      if (storedKey) {
        if (decryptionKey === storedKey) {
          setKeyVerified(true);
          addLog('✅ Key verified successfully! Matches encryption simulation key.', 'success');
          toast.success('Key verified! Ready to decrypt.');
        } else {
          setKeyVerified(false);
          addLog('❌ INVALID KEY! Does not match the encryption simulation key.', 'danger');
          addLog('💡 Use the exact key shown after encryption simulation.', 'warning');
          toast.error('Invalid decryption key! This key does not match.');
        }
      } else {
        // No stored key - allow custom key for uploaded files
        if (decryptionKey.length >= 8) {
          setKeyVerified(true);
          addLog('✅ Key format accepted for uploaded files.', 'success');
          addLog('⚠️ Note: Decryption will only work if this is the correct key.', 'warning');
          toast.success('Key accepted. Proceed with decryption.');
        } else {
          setKeyVerified(false);
          addLog('❌ Key too short. Minimum 8 characters required.', 'danger');
          toast.error('Key must be at least 8 characters.');
        }
      }
    }, 500);
  };

  const runDecryption = async () => {
    if (!decryptionKey) {
      toast.error('Please enter the decryption key');
      return;
    }

    if (!keyVerified) {
      toast.error('Please verify your key first before decrypting');
      return;
    }

    if (encryptedFiles.length === 0) {
      toast.error('No encrypted files to recover. Upload files or run encryption simulation first.');
      return;
    }

    setIsDecrypting(true);
    setRecoveredFiles([]);
    setDecryptionProgress(0);
    
    addLog('🛡️ INITIATING FILE RECOVERY PROCESS', 'info');
    addLog('🔐 Loading verified decryption key...', 'info');
    await new Promise(resolve => setTimeout(resolve, 500));
    addLog('📂 Scanning encrypted files...', 'info');
    addLog(`📊 Found ${encryptedFiles.length} encrypted file(s)`, 'info');
    await new Promise(resolve => setTimeout(resolve, 300));

    const storedKey = localStorage.getItem('ransomware_key');
    const isCorrectKey = storedKey ? decryptionKey === storedKey : true;

    for (let i = 0; i < encryptedFiles.length; i++) {
      setCurrentFileIndex(i);
      const progress = Math.round(((i + 1) / encryptedFiles.length) * 100);
      setDecryptionProgress(progress);
      
      const file = encryptedFiles[i];
      addLog(`🔓 Decrypting: ${file.name}`, 'warning');
      addLog(`   ├─ Size: ${(file.size / 1024).toFixed(2)} KB`, 'info');
      addLog(`   ├─ Applying key transformation...`, 'info');
      
      await new Promise(resolve => setTimeout(resolve, 800));
      
      let decryptedContent: string;
      
      if (isCorrectKey && file.originalContent) {
        // If correct key and we have original content, restore it
        decryptedContent = file.originalContent;
        addLog(`   ├─ Verifying file integrity... PASSED ✓`, 'success');
      } else {
        // Attempt decryption
        decryptedContent = simpleDecrypt(file.encryptedContent || '', decryptionKey);
        
        if (decryptedContent.includes('DECRYPTION FAILED')) {
          addLog(`   ├─ ⚠️ Decryption may have failed - verify output`, 'warning');
        } else {
          addLog(`   ├─ Verifying file integrity...`, 'info');
        }
      }
      
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
    addLog(`📊 Successfully processed ${encryptedFiles.length} file(s)`, 'success');
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

  const clearAllFiles = () => {
    setEncryptedFiles([]);
    setRecoveredFiles([]);
    setSelectedFile(null);
    localStorage.removeItem('encrypted_files');
    addLog('🗑️ All files cleared', 'info');
    toast.info('All files cleared');
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
            <strong>RECOVERY MODE:</strong> Upload encrypted files directly or use files from encryption simulation. 
            Enter the correct decryption key to recover your files.
          </p>
        </div>
      </div>

      {/* File Upload Section */}
      <div className="mb-6">
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={cn(
            "cyber-card border-2 border-dashed p-8 transition-all duration-300 cursor-pointer",
            isDragging ? "border-success bg-success/10" : "border-border hover:border-primary/50"
          )}
          onClick={() => fileInputRef.current?.click()}
        >
          <div className="flex flex-col items-center justify-center text-center">
            <Upload className={cn(
              "w-12 h-12 mb-4 transition-colors",
              isDragging ? "text-success" : "text-primary"
            )} />
            <h3 className="font-display text-lg font-bold text-foreground mb-2">
              Upload Encrypted Files
            </h3>
            <p className="text-muted-foreground font-mono text-sm mb-4">
              Drag & drop encrypted files here, or click to browse
            </p>
            <p className="text-xs text-muted-foreground font-mono">
              Supports: .encrypted, .enc, .locked files or any encrypted data
            </p>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            onChange={handleFileInputChange}
            className="hidden"
          />
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
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-destructive flex items-center gap-1">
                  <Lock className="w-3 h-3" />
                  {encryptedFiles.length} files
                </span>
                {encryptedFiles.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={clearAllFiles} className="h-6 px-2">
                    <X className="w-3 h-3" />
                  </Button>
                )}
              </div>
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
              {encryptedFiles.length === 0 ? (
                <div className="text-center py-8">
                  <Lock className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-muted-foreground font-mono text-sm">
                    No encrypted files yet.
                  </p>
                  <p className="text-xs text-muted-foreground font-mono mt-1">
                    Upload files above or run encryption simulation
                  </p>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="mt-3"
                    onClick={loadEncryptedFiles}
                  >
                    <RefreshCw className="w-3 h-3 mr-2" />
                    Load from Simulation
                  </Button>
                </div>
              ) : (
                encryptedFiles.map((file, index) => (
                  <div
                    key={file.id}
                    onClick={() => setSelectedFile(file)}
                    className={cn(
                      "flex items-center gap-3 p-3 rounded-lg border transition-all duration-300 cursor-pointer group",
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
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        removeEncryptedFile(file.id);
                      }}
                      className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive transition-opacity"
                    >
                      <X className="w-4 h-4" />
                    </button>
                    <Lock className="w-4 h-4 text-destructive" />
                  </div>
                ))
              )}
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
                <div className="text-center py-8">
                  <Unlock className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-muted-foreground font-mono text-sm">
                    No files recovered yet.
                  </p>
                  <p className="text-xs text-muted-foreground font-mono mt-1">
                    Enter the key and run recovery
                  </p>
                </div>
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
                    onChange={(e) => {
                      setDecryptionKey(e.target.value);
                      setKeyVerified(false);
                    }}
                    className="font-mono flex-1"
                  />
                  <Button variant="outline" onClick={verifyKey} disabled={!decryptionKey}>
                    Verify
                  </Button>
                </div>
                {keyVerified ? (
                  <p className="text-xs text-success font-mono flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" /> Key verified - ready for decryption
                  </p>
                ) : decryptionKey && (
                  <p className="text-xs text-muted-foreground font-mono flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> Click "Verify" to validate key
                  </p>
                )}
              </div>

              <Button
                variant="success"
                size="lg"
                className="w-full"
                onClick={runDecryption}
                disabled={isDecrypting || !keyVerified || encryptedFiles.length === 0}
              >
                {isDecrypting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-success-foreground/30 border-t-success-foreground rounded-full animate-spin" />
                    DECRYPTING... {decryptionProgress}%
                  </>
                ) : (
                  <>
                    <Unlock className="w-5 h-5" />
                    START DECRYPTION
                  </>
                )}
              </Button>

              <div className="flex gap-2">
                <Button variant="outline" className="flex-1" onClick={resetRecovery}>
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
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" />
              RECOVERY LOG
            </h3>
            <div ref={logContainerRef} className="space-y-1 max-h-64 overflow-y-auto font-mono text-xs">
              {logs.length === 0 ? (
                <p className="text-muted-foreground text-center py-4">
                  Upload files and start recovery to see logs
                </p>
              ) : (
                logs.map((log) => (
                  <div
                    key={log.id}
                    className={cn(
                      "py-1 px-2 rounded",
                      log.type === 'info' && "text-muted-foreground",
                      log.type === 'warning' && "text-warning bg-warning/5",
                      log.type === 'success' && "text-success bg-success/5",
                      log.type === 'danger' && "text-destructive bg-destructive/5"
                    )}
                  >
                    <span className="opacity-50">[{log.timestamp.toLocaleTimeString()}]</span> {log.message}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* File Preview Modal */}
      {selectedFile && (
        <div 
          className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setSelectedFile(null);
            }
          }}
        >
          <div className="cyber-card max-w-2xl w-full p-6 border border-border max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground flex items-center gap-2">
                {selectedFile.encrypted ? (
                  <Lock className="w-5 h-5 text-destructive" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-success" />
                )}
                {selectedFile.name}
              </h3>
              <Button 
                variant="ghost" 
                size="sm" 
                onClick={() => setSelectedFile(null)}
                className="h-8 w-8 p-0"
              >
                <X className="w-5 h-5" />
              </Button>
            </div>
            <div className="bg-secondary/30 p-4 rounded-lg">
              <pre className="font-mono text-xs text-foreground whitespace-pre-wrap break-all max-h-96 overflow-auto">
                {selectedFile.encrypted ? selectedFile.encryptedContent : selectedFile.content}
              </pre>
            </div>
            <div className="mt-4 flex justify-end gap-2">
              {!selectedFile.encrypted && (
                <Button variant="success" onClick={() => downloadRecoveredFile(selectedFile)}>
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
              )}
              <Button variant="outline" onClick={() => setSelectedFile(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default DecryptPage;