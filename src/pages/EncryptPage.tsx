import { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Lock, FileText, AlertTriangle, Play, Square, Trash2, Plus, Shield, Upload, File, Eye, X } from 'lucide-react';
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

const generateKey = (): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let key = '';
  for (let i = 0; i < 32; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
};

const simpleEncrypt = (text: string, key: string): string => {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return btoa(unescape(encodeURIComponent(result)));
};

const EncryptPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<SimFile[]>([]);
  const [encryptionKey, setEncryptionKey] = useState<string>('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(-1);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<SimFile | null>(null);
  const [encryptionProgress, setEncryptionProgress] = useState(0);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

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

  const handleFileUpload = async (uploadedFiles: FileList | null) => {
    if (!uploadedFiles) return;

    for (const file of Array.from(uploadedFiles)) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        const newFile: SimFile = {
          id: Date.now().toString() + Math.random(),
          name: file.name,
          content: content,
          size: file.size,
          type: file.type || 'text/plain',
          encrypted: false,
          originalContent: content
        };
        setFiles(prev => [...prev, newFile]);
        addLog(`📁 File uploaded: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`, 'info');
      };
      reader.readAsText(file);
    }
    toast.success(`${uploadedFiles.length} file(s) uploaded`);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    handleFileUpload(e.dataTransfer.files);
  };

  const runEncryption = async () => {
    const unencryptedFiles = files.filter(f => !f.encrypted);
    if (unencryptedFiles.length === 0) {
      toast.error('No files to encrypt');
      return;
    }

    setIsEncrypting(true);
    setEncryptionProgress(0);
    const key = generateKey();
    setEncryptionKey(key);
    
    addLog('🔑 Generating AES-256 encryption key...', 'info');
    await new Promise(resolve => setTimeout(resolve, 500));
    addLog(`🔐 Key generated: ${key.substring(0, 8)}${'*'.repeat(16)}`, 'warning');
    addLog('⚠️ RANSOMWARE SIMULATION INITIATED', 'danger');
    addLog('📂 Scanning target directory...', 'info');
    await new Promise(resolve => setTimeout(resolve, 300));
    addLog(`📊 Found ${unencryptedFiles.length} target file(s)`, 'info');

    for (let i = 0; i < files.length; i++) {
      if (files[i].encrypted) continue;
      
      setCurrentFileIndex(i);
      const progress = Math.round(((i + 1) / files.length) * 100);
      setEncryptionProgress(progress);
      
      addLog(`🔒 Encrypting: ${files[i].name}`, 'warning');
      addLog(`   ├─ Size: ${(files[i].size / 1024).toFixed(2)} KB`, 'info');
      addLog(`   ├─ Type: ${files[i].type}`, 'info');
      
      await new Promise(resolve => setTimeout(resolve, 600));
      
      const encryptedContent = simpleEncrypt(files[i].content, key);
      
      addLog(`   ├─ Entropy analysis: HIGH (encrypted)`, 'warning');
      addLog(`   └─ Status: ENCRYPTED ✓`, 'danger');
      
      setFiles(prev => prev.map((f, idx) => 
        idx === i ? { 
          ...f, 
          encrypted: true, 
          encryptedContent,
          originalContent: f.content,
          content: encryptedContent
        } : f
      ));
      
      await new Promise(resolve => setTimeout(resolve, 200));
    }

    setCurrentFileIndex(-1);
    setIsEncrypting(false);
    setEncryptionProgress(100);
    addLog('💀 ALL FILES ENCRYPTED', 'danger');
    addLog('📝 Ransom note generated: README_DECRYPT.txt', 'danger');
    addLog('🌐 C2 beacon sent (simulated)', 'warning');
    
    // Store the key for decryption page
    localStorage.setItem('ransomware_key', key);
    localStorage.setItem('encrypted_files', JSON.stringify(files.map((f, idx) => ({
      ...f,
      encrypted: true,
      encryptedContent: simpleEncrypt(f.content, key)
    }))));
    
    toast.error('Ransomware simulation complete! All files encrypted.');
  };

  const resetSimulation = () => {
    setFiles(files.map(f => ({ 
      ...f, 
      encrypted: false, 
      encryptedContent: undefined,
      content: f.originalContent || f.content
    })));
    setEncryptionKey('');
    setLogs([]);
    setCurrentFileIndex(-1);
    setEncryptionProgress(0);
    localStorage.removeItem('ransomware_key');
    localStorage.removeItem('encrypted_files');
    toast.success('Simulation reset');
  };

  const addFile = () => {
    if (!newFileName || !newFileContent) {
      toast.error('Please enter file name and content');
      return;
    }
    const newFile: SimFile = {
      id: Date.now().toString(),
      name: newFileName,
      content: newFileContent,
      size: newFileContent.length,
      type: 'text/plain',
      encrypted: false,
      originalContent: newFileContent
    };
    setFiles(prev => [...prev, newFile]);
    setNewFileName('');
    setNewFileContent('');
    addLog(`📁 File created: ${newFileName}`, 'info');
    toast.success('File added to simulation');
  };

  const removeFile = (id: string) => {
    const file = files.find(f => f.id === id);
    setFiles(prev => prev.filter(f => f.id !== id));
    if (file) addLog(`🗑️ File removed: ${file.name}`, 'info');
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-destructive text-glow-red tracking-wider flex items-center gap-3">
          <Lock className="w-8 h-8" />
          ENCRYPTION SIMULATION
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Real-time ransomware file encryption simulation
        </p>
      </div>

      {/* Warning Banner */}
      <div className="mb-6 p-4 rounded-lg bg-destructive/10 border border-destructive/30">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0" />
          <p className="text-sm font-mono text-destructive">
            <strong>SIMULATION MODE:</strong> Upload real files or create test files. Encryption happens in-memory using XOR cipher simulation.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* File System Panel */}
        <div className="space-y-6">
          {/* Drag & Drop Upload */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={cn(
              "cyber-card p-8 border-2 border-dashed transition-all cursor-pointer",
              isDragging 
                ? "border-primary bg-primary/10" 
                : "border-border hover:border-primary/50"
            )}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => handleFileUpload(e.target.files)}
            />
            <div className="relative z-10 text-center">
              <Upload className={cn(
                "w-12 h-12 mx-auto mb-3 transition-colors",
                isDragging ? "text-primary" : "text-muted-foreground"
              )} />
              <p className="font-mono text-foreground">
                {isDragging ? "Drop files here" : "Drag & drop files or click to upload"}
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                Upload any files to simulate ransomware attack
              </p>
            </div>
          </div>

          {/* File List */}
          <div className="cyber-card p-5 border border-border">
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                  TARGET FILES
                </h3>
                <span className="text-xs font-mono text-muted-foreground">
                  {files.filter(f => f.encrypted).length}/{files.length} encrypted
                </span>
              </div>

              {/* Progress Bar */}
              {isEncrypting && (
                <div className="mb-4">
                  <div className="flex justify-between text-xs font-mono text-muted-foreground mb-1">
                    <span>Encryption Progress</span>
                    <span>{encryptionProgress}%</span>
                  </div>
                  <div className="h-2 bg-secondary rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-destructive transition-all duration-300"
                      style={{ width: `${encryptionProgress}%` }}
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2 mb-4 max-h-64 overflow-y-auto">
                {files.length === 0 ? (
                  <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                    No files added. Upload or create files above.
                  </p>
                ) : (
                  files.map((file, index) => (
                    <div
                      key={file.id}
                      onClick={() => setSelectedFile(file)}
                      className={cn(
                        "flex items-center gap-3 p-3 rounded-lg border transition-all duration-300 cursor-pointer",
                        file.encrypted 
                          ? "bg-destructive/10 border-destructive/30" 
                          : "bg-secondary/30 border-border/50 hover:border-primary/50",
                        currentFileIndex === index && "animate-pulse border-warning",
                        selectedFile?.id === file.id && "ring-2 ring-primary"
                      )}
                    >
                      <File className={cn(
                        "w-5 h-5 flex-shrink-0",
                        file.encrypted ? "text-destructive" : "text-primary"
                      )} />
                      <div className="flex-1 min-w-0">
                        <p className="font-mono text-sm text-foreground truncate">
                          {file.name}{file.encrypted && '.encrypted'}
                        </p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {(file.size / 1024).toFixed(2)} KB • {file.type}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button 
                          onClick={(e) => { e.stopPropagation(); setSelectedFile(file); }}
                          className="text-muted-foreground hover:text-primary"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        {file.encrypted ? (
                          <Lock className="w-4 h-4 text-destructive" />
                        ) : (
                          <button 
                            onClick={(e) => { e.stopPropagation(); removeFile(file.id); }}
                            className="text-muted-foreground hover:text-destructive"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Add File */}
              <div className="space-y-2 p-3 bg-secondary/20 rounded-lg">
                <Input
                  placeholder="filename.txt"
                  value={newFileName}
                  onChange={(e) => setNewFileName(e.target.value)}
                  className="font-mono text-sm"
                />
                <Input
                  placeholder="File content..."
                  value={newFileContent}
                  onChange={(e) => setNewFileContent(e.target.value)}
                  className="font-mono text-sm"
                />
                <Button variant="outline" size="sm" onClick={addFile} className="w-full">
                  <Plus className="w-4 h-4 mr-2" /> Create Test File
                </Button>
              </div>
            </div>
          </div>
        </div>

        {/* Control Panel */}
        <div className="space-y-6">
          {/* Encryption Controls */}
          <div className="cyber-card p-5 border border-border">
            <div className="relative z-10">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
                ENCRYPTION CONTROLS
              </h3>

              <div className="space-y-4">
                <Button
                  variant="danger"
                  size="lg"
                  className="w-full"
                  onClick={runEncryption}
                  disabled={isEncrypting || files.every(f => f.encrypted) || files.length === 0}
                >
                  {isEncrypting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-destructive-foreground/30 border-t-destructive-foreground rounded-full animate-spin" />
                      ENCRYPTING... {encryptionProgress}%
                    </>
                  ) : (
                    <>
                      <Play className="w-5 h-5" />
                      RUN RANSOMWARE SIM
                    </>
                  )}
                </Button>

                <Button
                  variant="outline"
                  size="lg"
                  className="w-full"
                  onClick={resetSimulation}
                  disabled={isEncrypting}
                >
                  <Square className="w-5 h-5" />
                  RESET SIMULATION
                </Button>
              </div>

              {encryptionKey && (
                <div className="mt-4 p-3 bg-warning/10 border border-warning/30 rounded-lg">
                  <p className="text-xs font-mono text-warning mb-1">🔑 ENCRYPTION KEY (SAVE THIS!):</p>
                  <code className="text-xs font-mono text-foreground break-all select-all">{encryptionKey}</code>
                </div>
              )}
            </div>
          </div>

          {/* File Preview */}
          {selectedFile && (
            <div className="cyber-card p-5 border border-border">
              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                    FILE PREVIEW: {selectedFile.name}
                  </h3>
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    onClick={() => setSelectedFile(null)}
                    className="h-8 w-8 p-0"
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>
                <div className="bg-background/50 rounded-lg p-3 max-h-32 overflow-auto font-mono text-xs">
                  {selectedFile.encrypted ? (
                    <p className="text-destructive break-all">{selectedFile.encryptedContent?.substring(0, 500)}...</p>
                  ) : (
                    <p className="text-accent">{selectedFile.content.substring(0, 500)}</p>
                  )}
                </div>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => setSelectedFile(null)}
                  className="mt-3"
                >
                  Close Preview
                </Button>
              </div>
            </div>
          )}

          {/* Activity Log */}
          <div className="cyber-card p-5 border border-border">
            <div className="relative z-10">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
                REAL-TIME ACTIVITY LOG
              </h3>
              <div 
                ref={logContainerRef}
                className="bg-background/50 rounded-lg p-3 h-64 overflow-y-auto font-mono text-xs"
              >
                {logs.length === 0 ? (
                  <p className="text-muted-foreground">Waiting for simulation to start...</p>
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
      </div>

      {/* Ransom Note */}
      {files.every(f => f.encrypted) && files.length > 0 && (
        <div className="mt-6 cyber-card p-6 border-2 border-destructive animate-pulse">
          <div className="relative z-10 text-center">
            <h2 className="font-display text-2xl font-bold text-destructive mb-4">
              💀 YOUR FILES HAVE BEEN ENCRYPTED 💀
            </h2>
            <p className="font-mono text-foreground mb-4">
              All {files.length} file(s) have been encrypted with AES-256 encryption.
            </p>
            <div className="bg-background/50 p-4 rounded-lg text-left font-mono text-sm mb-4 max-w-lg mx-auto">
              <p className="text-destructive mb-2">README_DECRYPT.txt</p>
              <p className="text-muted-foreground">
                Your files have been encrypted by CryptoLocker.<br/>
                To decrypt your files, you need the decryption key.<br/><br/>
                Go to DECRYPT & RECOVER section and enter your key.
              </p>
            </div>
            <Button variant="success" onClick={() => navigate('/decrypt')}>
              <Shield className="w-4 h-4 mr-2" />
              GO TO RECOVERY
            </Button>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default EncryptPage;
