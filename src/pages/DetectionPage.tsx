import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Activity, Shield, AlertTriangle, Eye, Cpu, HardDrive, Network, Play, Square, CheckCircle, FileSearch, Upload, Zap, BarChart3, Lock } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface ProcessInfo {
  id: string;
  name: string;
  pid: number;
  cpu: number;
  memory: number;
  status: 'normal' | 'suspicious' | 'blocked';
  fileChanges: number;
  entropy: number;
  networkActivity: boolean;
}

interface Detection {
  id: string;
  type: 'info' | 'warning' | 'critical';
  message: string;
  timestamp: Date;
  source: string;
}

interface FileAnalysis {
  name: string;
  entropy: number;
  isSuspicious: boolean;
  type: string;
  size: number;
}

const DetectionPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [analyzedFiles, setAnalyzedFiles] = useState<FileAnalysis[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [stats, setStats] = useState({
    filesScanned: 0,
    threatsBlocked: 0,
    cpuUsage: 0,
    networkActivity: 0,
    entropyAlerts: 0,
    processesMonitored: 0
  });

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  const addDetection = useCallback((type: 'info' | 'warning' | 'critical', message: string, source: string = 'System') => {
    setDetections(prev => [{
      id: Date.now().toString() + Math.random(),
      type,
      message,
      timestamp: new Date(),
      source
    }, ...prev.slice(0, 49)]);
  }, []);

  // Calculate entropy (randomness) of data - high entropy suggests encryption
  const calculateEntropy = (data: string): number => {
    const len = data.length;
    if (len === 0) return 0;
    
    const freq: { [key: string]: number } = {};
    for (const char of data) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return Math.min(entropy / 8, 1) * 100; // Normalize to percentage
  };

  // Analyze uploaded files for ransomware indicators
  const analyzeFile = async (file: File) => {
    return new Promise<FileAnalysis>((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        const entropy = calculateEntropy(content);
        const isSuspicious = entropy > 70 || 
          file.name.includes('.encrypted') || 
          file.name.includes('.locked') ||
          file.name.includes('.crypted');
        
        resolve({
          name: file.name,
          entropy,
          isSuspicious,
          type: file.type || 'unknown',
          size: file.size
        });
      };
      reader.readAsText(file);
    });
  };

  const handleFileUpload = async (files: FileList | null) => {
    if (!files) return;
    
    setIsAnalyzing(true);
    addDetection('info', `Initiating scan of ${files.length} file(s)...`, 'File Scanner');
    
    const results: FileAnalysis[] = [];
    
    for (const file of Array.from(files)) {
      addDetection('info', `Scanning: ${file.name}`, 'File Scanner');
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const analysis = await analyzeFile(file);
      results.push(analysis);
      
      if (analysis.isSuspicious) {
        addDetection('critical', `HIGH ENTROPY DETECTED: ${file.name} (${analysis.entropy.toFixed(1)}%) - Possible encryption!`, 'Entropy Analyzer');
        setStats(prev => ({ ...prev, entropyAlerts: prev.entropyAlerts + 1 }));
      } else {
        addDetection('info', `File OK: ${file.name} (Entropy: ${analysis.entropy.toFixed(1)}%)`, 'File Scanner');
      }
      
      setStats(prev => ({ ...prev, filesScanned: prev.filesScanned + 1 }));
    }
    
    setAnalyzedFiles(prev => [...results, ...prev]);
    setIsAnalyzing(false);
    
    const suspicious = results.filter(r => r.isSuspicious).length;
    if (suspicious > 0) {
      toast.warning(`Found ${suspicious} suspicious file(s)!`);
    } else {
      toast.success('All files appear normal');
    }
  };

  // Real-time process monitoring simulation
  useEffect(() => {
    if (!isMonitoring) return;

    const interval = setInterval(() => {
      // Update stats
      setStats(prev => ({
        ...prev,
        cpuUsage: Math.floor(Math.random() * 40) + 10,
        networkActivity: Math.floor(Math.random() * 100),
        processesMonitored: prev.processesMonitored + 1
      }));

      // Simulate process monitoring with realistic data
      const processNames = [
        'chrome.exe', 'node.exe', 'explorer.exe', 'python.exe', 'vscode.exe',
        'cryptolocker.exe', 'ransomware.exe', 'svchost.exe', 'System', 'notepad.exe'
      ];
      
      const name = processNames[Math.floor(Math.random() * processNames.length)];
      const fileChanges = Math.floor(Math.random() * 20);
      const cpu = Math.floor(Math.random() * 100);
      const entropy = Math.floor(Math.random() * 100);
      
      const newProcess: ProcessInfo = {
        id: Date.now().toString() + Math.random(),
        name,
        pid: Math.floor(Math.random() * 10000) + 1000,
        cpu,
        memory: Math.floor(Math.random() * 500) + 50,
        status: 'normal',
        fileChanges,
        entropy,
        networkActivity: Math.random() > 0.7
      };

      // Ransomware detection heuristics
      const isSuspiciousName = ['cryptolocker.exe', 'ransomware.exe'].includes(name);
      const hasHighFileChanges = fileChanges > 12;
      const hasHighEntropy = entropy > 75;
      const hasHighCpu = cpu > 85;
      
      if (isSuspiciousName || (hasHighFileChanges && hasHighCpu)) {
        newProcess.status = 'suspicious';
        addDetection('warning', `Suspicious activity: ${name} (PID: ${newProcess.pid}) - ${fileChanges} file ops/s`, 'Process Monitor');
        
        // Auto-block known malware or extreme behavior
        if (isSuspiciousName || fileChanges > 15) {
          newProcess.status = 'blocked';
          addDetection('critical', `THREAT BLOCKED: ${name} (PID: ${newProcess.pid}) - Ransomware behavior detected!`, 'Threat Prevention');
          setStats(prev => ({ ...prev, threatsBlocked: prev.threatsBlocked + 1 }));
          toast.warning(`Threat blocked: ${name}`);
        }
      } else if (hasHighEntropy) {
        addDetection('warning', `High entropy operation: ${name} - Possible encryption activity`, 'Entropy Monitor');
      } else {
        addDetection('info', `Process scan: ${name} (PID: ${newProcess.pid}) - Normal`, 'Process Monitor');
      }

      setProcesses(prev => [newProcess, ...prev.slice(0, 14)]);
    }, 2000);

    return () => clearInterval(interval);
  }, [isMonitoring, addDetection]);

  const startMonitoring = () => {
    setIsMonitoring(true);
    addDetection('info', 'Real-time detection engine ACTIVATED', 'System');
    addDetection('info', 'Loading behavioral analysis modules...', 'System');
    addDetection('info', 'Entropy monitoring enabled', 'Entropy Monitor');
    addDetection('info', 'Process heuristics loaded', 'Process Monitor');
    toast.success('Real-time monitoring activated');
  };

  const stopMonitoring = () => {
    setIsMonitoring(false);
    addDetection('info', 'Detection engine paused', 'System');
    toast.info('Monitoring paused');
  };

  const clearLogs = () => {
    setDetections([]);
    setProcesses([]);
    setAnalyzedFiles([]);
    setStats({ filesScanned: 0, threatsBlocked: 0, cpuUsage: 0, networkActivity: 0, entropyAlerts: 0, processesMonitored: 0 });
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-warning text-glow-cyan tracking-wider flex items-center gap-3">
          <Activity className="w-8 h-8" />
          DETECTION MONITOR
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Real-time behavioral analysis, entropy detection, and threat prevention
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <HardDrive className="w-6 h-6 text-primary" />
            <div>
              <p className="text-xl font-display font-bold text-foreground">{stats.filesScanned}</p>
              <p className="text-xs font-mono text-muted-foreground">Files Scanned</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Shield className="w-6 h-6 text-success" />
            <div>
              <p className="text-xl font-display font-bold text-success">{stats.threatsBlocked}</p>
              <p className="text-xs font-mono text-muted-foreground">Threats Blocked</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Cpu className="w-6 h-6 text-warning" />
            <div>
              <p className="text-xl font-display font-bold text-foreground">{stats.cpuUsage}%</p>
              <p className="text-xs font-mono text-muted-foreground">CPU Usage</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Network className="w-6 h-6 text-primary" />
            <div>
              <p className="text-xl font-display font-bold text-foreground">{stats.networkActivity}%</p>
              <p className="text-xs font-mono text-muted-foreground">Network</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <BarChart3 className="w-6 h-6 text-destructive" />
            <div>
              <p className="text-xl font-display font-bold text-destructive">{stats.entropyAlerts}</p>
              <p className="text-xs font-mono text-muted-foreground">Entropy Alerts</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Zap className="w-6 h-6 text-accent" />
            <div>
              <p className="text-xl font-display font-bold text-foreground">{stats.processesMonitored}</p>
              <p className="text-xs font-mono text-muted-foreground">Processes</p>
            </div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-4 mb-6">
        <Button
          variant={isMonitoring ? "danger" : "success"}
          size="lg"
          onClick={isMonitoring ? stopMonitoring : startMonitoring}
        >
          {isMonitoring ? (
            <>
              <Square className="w-5 h-5" />
              STOP MONITORING
            </>
          ) : (
            <>
              <Play className="w-5 h-5" />
              START MONITORING
            </>
          )}
        </Button>
        
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => handleFileUpload(e.target.files)}
        />
        <Button 
          variant="cyber" 
          size="lg"
          onClick={() => fileInputRef.current?.click()}
          disabled={isAnalyzing}
        >
          {isAnalyzing ? (
            <>
              <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
              ANALYZING...
            </>
          ) : (
            <>
              <FileSearch className="w-5 h-5" />
              SCAN FILES
            </>
          )}
        </Button>
        
        <Button variant="outline" onClick={clearLogs}>
          Clear Logs
        </Button>
        
        <div className="flex items-center gap-2 ml-auto">
          <div className={cn(
            "w-3 h-3 rounded-full",
            isMonitoring ? "bg-success animate-pulse" : "bg-muted"
          )} />
          <span className="font-mono text-sm text-muted-foreground">
            {isMonitoring ? 'ACTIVE' : 'PAUSED'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Process Monitor */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <Eye className="w-5 h-5 text-primary" />
              PROCESS MONITOR
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {processes.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  Start monitoring to see process activity
                </p>
              ) : (
                processes.map((proc) => (
                  <div
                    key={proc.id}
                    className={cn(
                      "flex items-center gap-3 p-3 rounded-lg border transition-all",
                      proc.status === 'normal' && "bg-secondary/30 border-border/50",
                      proc.status === 'suspicious' && "bg-warning/10 border-warning/30",
                      proc.status === 'blocked' && "bg-destructive/10 border-destructive/30"
                    )}
                  >
                    <div className={cn(
                      "w-2 h-2 rounded-full flex-shrink-0",
                      proc.status === 'normal' && "bg-success",
                      proc.status === 'suspicious' && "bg-warning animate-pulse",
                      proc.status === 'blocked' && "bg-destructive"
                    )} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="font-mono text-sm text-foreground truncate">{proc.name}</p>
                        <span className="text-xs text-muted-foreground">PID: {proc.pid}</span>
                      </div>
                      <div className="flex gap-4 text-xs text-muted-foreground font-mono">
                        <span>CPU: {proc.cpu}%</span>
                        <span>MEM: {proc.memory}MB</span>
                        <span>Files: {proc.fileChanges}/s</span>
                        <span>Entropy: {proc.entropy}%</span>
                      </div>
                    </div>
                    {proc.status === 'blocked' && (
                      <span className="text-xs font-mono text-destructive px-2 py-1 bg-destructive/20 rounded flex-shrink-0">
                        BLOCKED
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Detection Log */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-warning" />
              DETECTION LOG
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {detections.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  No detections yet
                </p>
              ) : (
                detections.map((det) => (
                  <div
                    key={det.id}
                    className={cn(
                      "p-3 rounded-lg border animate-fade-in",
                      det.type === 'info' && "bg-primary/5 border-primary/20",
                      det.type === 'warning' && "bg-warning/10 border-warning/30",
                      det.type === 'critical' && "bg-destructive/10 border-destructive/30"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {det.type === 'info' && <CheckCircle className="w-3 h-3 text-primary" />}
                      {det.type === 'warning' && <AlertTriangle className="w-3 h-3 text-warning" />}
                      {det.type === 'critical' && <Shield className="w-3 h-3 text-destructive" />}
                      <span className="text-xs font-mono text-muted-foreground">
                        [{det.source}] {det.timestamp.toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="font-mono text-sm text-foreground">{det.message}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* File Analysis Results */}
      {analyzedFiles.length > 0 && (
        <div className="mt-6 cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <FileSearch className="w-5 h-5 text-accent" />
              FILE ANALYSIS RESULTS
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {analyzedFiles.map((file, idx) => (
                <div
                  key={idx}
                  className={cn(
                    "p-4 rounded-lg border",
                    file.isSuspicious 
                      ? "bg-destructive/10 border-destructive/30" 
                      : "bg-success/10 border-success/30"
                  )}
                >
                  <div className="flex items-center gap-2 mb-2">
                    {file.isSuspicious ? (
                      <Lock className="w-4 h-4 text-destructive" />
                    ) : (
                      <CheckCircle className="w-4 h-4 text-success" />
                    )}
                    <p className="font-mono text-sm text-foreground truncate">{file.name}</p>
                  </div>
                  <div className="space-y-1 text-xs font-mono text-muted-foreground">
                    <div className="flex justify-between">
                      <span>Entropy:</span>
                      <span className={file.entropy > 70 ? "text-destructive" : "text-success"}>
                        {file.entropy.toFixed(1)}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Size:</span>
                      <span>{(file.size / 1024).toFixed(2)} KB</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Status:</span>
                      <span className={file.isSuspicious ? "text-destructive" : "text-success"}>
                        {file.isSuspicious ? "SUSPICIOUS" : "CLEAN"}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default DetectionPage;
