import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { 
  ClipboardList, CheckCircle, Circle, AlertTriangle, FileText, Download, Clock,
  Shield, Wifi, WifiOff, Server, Database, Terminal, Eye, Search, Filter,
  Play, Pause, RotateCcw, Activity, AlertCircle, Bug, Lock, Unlock
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface IncidentStep {
  id: string;
  title: string;
  description: string;
  status: 'pending' | 'in-progress' | 'completed';
  timestamp?: Date;
  details?: string[];
}

interface LogEntry {
  id: string;
  action: string;
  timestamp: Date;
  severity: 'info' | 'warning' | 'critical' | 'success';
  source: string;
  details?: string;
}

interface Asset {
  id: string;
  name: string;
  type: 'workstation' | 'server' | 'network' | 'database';
  status: 'healthy' | 'infected' | 'isolated' | 'recovered';
  ip: string;
  lastSeen: Date;
}

interface ThreatIndicator {
  id: string;
  type: 'hash' | 'ip' | 'domain' | 'file';
  value: string;
  confidence: 'high' | 'medium' | 'low';
  source: string;
}

const IncidentPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [logFilter, setLogFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const logContainerRef = useRef<HTMLDivElement>(null);
  
  const [assets, setAssets] = useState<Asset[]>([
    { id: '1', name: 'WORKSTATION-01', type: 'workstation', status: 'healthy', ip: '192.168.1.101', lastSeen: new Date() },
    { id: '2', name: 'WORKSTATION-02', type: 'workstation', status: 'healthy', ip: '192.168.1.102', lastSeen: new Date() },
    { id: '3', name: 'FILE-SERVER-01', type: 'server', status: 'healthy', ip: '192.168.1.10', lastSeen: new Date() },
    { id: '4', name: 'DB-SERVER-01', type: 'database', status: 'healthy', ip: '192.168.1.20', lastSeen: new Date() },
    { id: '5', name: 'FIREWALL-01', type: 'network', status: 'healthy', ip: '192.168.1.1', lastSeen: new Date() },
  ]);

  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);

  const [steps, setSteps] = useState<IncidentStep[]>([
    { 
      id: '1', 
      title: 'Detection & Analysis', 
      description: 'Identify the threat and assess the scope of the incident',
      status: 'pending',
      details: [
        'Monitor SIEM alerts for anomalies',
        'Analyze endpoint detection alerts',
        'Identify patient zero (initial infection)',
        'Determine ransomware variant'
      ]
    },
    { 
      id: '2', 
      title: 'Containment', 
      description: 'Isolate affected systems to prevent lateral movement',
      status: 'pending',
      details: [
        'Disconnect infected hosts from network',
        'Block malicious IPs at firewall',
        'Disable compromised accounts',
        'Segment network to limit spread'
      ]
    },
    { 
      id: '3', 
      title: 'Eradication', 
      description: 'Remove malware and malicious artifacts',
      status: 'pending',
      details: [
        'Terminate malicious processes',
        'Delete ransomware executables',
        'Clean registry entries',
        'Remove persistence mechanisms'
      ]
    },
    { 
      id: '4', 
      title: 'Recovery', 
      description: 'Restore systems and data from clean backups',
      status: 'pending',
      details: [
        'Verify backup integrity',
        'Restore from clean backups',
        'Rebuild compromised systems',
        'Validate data integrity'
      ]
    },
    { 
      id: '5', 
      title: 'Lessons Learned', 
      description: 'Document findings and improve security posture',
      status: 'pending',
      details: [
        'Create incident timeline',
        'Document IOCs discovered',
        'Update detection rules',
        'Recommend security improvements'
      ]
    },
  ]);

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

  const addLog = (action: string, severity: LogEntry['severity'], source: string, details?: string) => {
    setLogs(prev => [...prev, {
      id: Date.now().toString() + Math.random(),
      action,
      timestamp: new Date(),
      severity,
      source,
      details
    }]);
  };

  const updateAssetStatus = (assetId: string, status: Asset['status']) => {
    setAssets(prev => prev.map(a => 
      a.id === assetId ? { ...a, status, lastSeen: new Date() } : a
    ));
  };

  const addIndicator = (type: ThreatIndicator['type'], value: string, confidence: ThreatIndicator['confidence'], source: string) => {
    setIndicators(prev => [...prev, {
      id: Date.now().toString(),
      type,
      value,
      confidence,
      source
    }]);
  };

  const runIncidentResponse = async () => {
    if (isPaused) {
      setIsPaused(false);
      return;
    }

    setIsRunning(true);
    setCurrentStep(0);
    setLogs([]);
    setIndicators([]);
    
    // Reset assets
    setAssets(prev => prev.map(a => ({ ...a, status: 'healthy' as const })));
    
    // PHASE 1: Detection & Analysis
    setCurrentStep(0);
    setSteps(prev => prev.map((s, idx) => idx === 0 ? { ...s, status: 'in-progress' } : s));
    
    addLog('🔍 Initiating threat detection scan...', 'info', 'SIEM');
    await delay(600);
    
    addLog('⚠️ Anomalous file encryption activity detected', 'warning', 'EDR', 'High entropy file modifications on WORKSTATION-01');
    await delay(500);
    
    addLog('🚨 ALERT: Ransomware signature matched - LockBit 3.0', 'critical', 'AV Engine', 'SHA256: 3d4c5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e');
    addIndicator('hash', '3d4c5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e', 'high', 'VirusTotal');
    await delay(500);
    
    updateAssetStatus('1', 'infected');
    addLog('🎯 Patient Zero identified: WORKSTATION-01', 'critical', 'Analysis', 'User: jsmith@company.com');
    await delay(500);
    
    addLog('📊 Scope assessment: 1 confirmed infected, 4 at risk', 'warning', 'SOC Analyst');
    addIndicator('ip', '185.220.101.45', 'high', 'C2 Traffic Analysis');
    await delay(500);
    
    setSteps(prev => prev.map((s, idx) => idx === 0 ? { ...s, status: 'completed', timestamp: new Date() } : s));
    
    // PHASE 2: Containment
    setCurrentStep(1);
    setSteps(prev => prev.map((s, idx) => idx === 1 ? { ...s, status: 'in-progress' } : s));
    
    addLog('🔌 Initiating network isolation for WORKSTATION-01', 'info', 'Network Ops');
    await delay(600);
    
    updateAssetStatus('1', 'isolated');
    addLog('✅ WORKSTATION-01 isolated from network', 'success', 'Firewall');
    await delay(500);
    
    addLog('🛡️ Blocking malicious C2 IP: 185.220.101.45', 'info', 'Firewall');
    await delay(400);
    addLog('✅ IP blocked at perimeter firewall', 'success', 'Firewall');
    await delay(400);
    
    addLog('🔒 Disabling potentially compromised account: jsmith', 'warning', 'Active Directory');
    await delay(500);
    addLog('✅ Account disabled and password reset queued', 'success', 'Active Directory');
    await delay(400);
    
    addLog('🌐 Implementing network segmentation', 'info', 'Network Ops');
    await delay(600);
    addLog('✅ Containment barriers established', 'success', 'SOC');
    
    setSteps(prev => prev.map((s, idx) => idx === 1 ? { ...s, status: 'completed', timestamp: new Date() } : s));
    
    // PHASE 3: Eradication
    setCurrentStep(2);
    setSteps(prev => prev.map((s, idx) => idx === 2 ? { ...s, status: 'in-progress' } : s));
    
    addLog('🔎 Scanning for malicious processes on WORKSTATION-01', 'info', 'EDR');
    await delay(600);
    
    addLog('💀 Found: lockbit.exe (PID: 4521)', 'critical', 'Process Monitor');
    addIndicator('file', 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\lockbit.exe', 'high', 'EDR');
    await delay(400);
    
    addLog('🗑️ Terminating malicious process PID: 4521', 'warning', 'EDR');
    await delay(500);
    addLog('✅ Process terminated successfully', 'success', 'EDR');
    await delay(400);
    
    addLog('🔍 Removing persistence mechanisms...', 'info', 'EDR');
    await delay(500);
    addLog('📝 Registry key deleted: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\LockBit', 'success', 'Registry');
    await delay(400);
    
    addLog('🧹 Cleaning malware artifacts...', 'info', 'EDR');
    await delay(600);
    addLog('✅ All known malware components removed', 'success', 'EDR');
    
    setSteps(prev => prev.map((s, idx) => idx === 2 ? { ...s, status: 'completed', timestamp: new Date() } : s));
    
    // PHASE 4: Recovery
    setCurrentStep(3);
    setSteps(prev => prev.map((s, idx) => idx === 3 ? { ...s, status: 'in-progress' } : s));
    
    addLog('📂 Locating backup systems...', 'info', 'Backup Server');
    await delay(600);
    
    addLog('💾 Backup found: 3 restore points available', 'info', 'Backup Server', 'Last clean backup: 2 hours ago');
    await delay(400);
    
    addLog('✅ Backup integrity verified - clean', 'success', 'Backup Server');
    await delay(500);
    
    addLog('🔄 Initiating file recovery for WORKSTATION-01...', 'info', 'Recovery');
    await delay(800);
    
    addLog('📊 Restoring 1,247 encrypted files...', 'info', 'Recovery');
    await delay(600);
    
    updateAssetStatus('1', 'recovered');
    addLog('✅ File recovery complete: 1,247 files restored', 'success', 'Recovery');
    await delay(400);
    
    addLog('🔌 Reconnecting WORKSTATION-01 to network...', 'info', 'Network Ops');
    await delay(500);
    addLog('✅ System restored to operational status', 'success', 'SOC');
    
    setSteps(prev => prev.map((s, idx) => idx === 3 ? { ...s, status: 'completed', timestamp: new Date() } : s));
    
    // PHASE 5: Lessons Learned
    setCurrentStep(4);
    setSteps(prev => prev.map((s, idx) => idx === 4 ? { ...s, status: 'in-progress' } : s));
    
    addLog('📝 Generating incident timeline...', 'info', 'SOC Analyst');
    await delay(600);
    
    addLog('📊 Documenting Indicators of Compromise (IOCs)...', 'info', 'Threat Intel');
    await delay(500);
    addLog(`✅ ${indicators.length + 2} IOCs catalogued for future detection`, 'success', 'Threat Intel');
    await delay(400);
    
    addLog('🔧 Creating new detection rules...', 'info', 'SIEM');
    await delay(600);
    addLog('✅ 3 new SIEM correlation rules deployed', 'success', 'SIEM');
    await delay(400);
    
    addLog('📋 Generating final incident report...', 'info', 'SOC Analyst');
    await delay(600);
    addLog('✅ Incident report ready for review', 'success', 'SOC Analyst');
    addLog('🎉 INCIDENT RESPONSE COMPLETE', 'success', 'System');
    
    setSteps(prev => prev.map((s, idx) => idx === 4 ? { ...s, status: 'completed', timestamp: new Date() } : s));
    
    setIsRunning(false);
    toast.success('Incident response workflow completed!');
  };

  const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  const pauseWorkflow = () => {
    setIsPaused(true);
  };

  const resetWorkflow = () => {
    setSteps(steps.map(s => ({ ...s, status: 'pending', timestamp: undefined })));
    setLogs([]);
    setCurrentStep(0);
    setIsRunning(false);
    setIsPaused(false);
    setIndicators([]);
    setAssets(prev => prev.map(a => ({ ...a, status: 'healthy' as const })));
    toast.info('Workflow reset');
  };

  const exportReport = () => {
    const report = `
================================================================================
                        INCIDENT RESPONSE REPORT
================================================================================
Generated: ${new Date().toLocaleString()}
Incident ID: IR-${Date.now().toString().slice(-8)}

================================================================================
EXECUTIVE SUMMARY
================================================================================
Incident Type: Ransomware Attack
Variant: LockBit 3.0
Impact: 1 workstation compromised, 1,247 files encrypted
Resolution: Full recovery from backup, no data loss

================================================================================
TIMELINE
================================================================================
${steps.filter(s => s.timestamp).map(s => 
  `[${s.timestamp?.toLocaleTimeString()}] ${s.title.toUpperCase()}
   Status: ${s.status.toUpperCase()}
   ${s.details?.map(d => `   - ${d}`).join('\n') || ''}`
).join('\n\n')}

================================================================================
INDICATORS OF COMPROMISE (IOCs)
================================================================================
${indicators.map(i => `[${i.type.toUpperCase()}] ${i.value} (Confidence: ${i.confidence}, Source: ${i.source})`).join('\n')}

================================================================================
AFFECTED ASSETS
================================================================================
${assets.filter(a => a.status !== 'healthy').map(a => 
  `- ${a.name} (${a.ip}) - Status: ${a.status.toUpperCase()}`
).join('\n') || 'All assets recovered to healthy state'}

================================================================================
ACTIVITY LOG
================================================================================
${logs.map(l => `[${l.timestamp.toLocaleTimeString()}] [${l.severity.toUpperCase()}] [${l.source}] ${l.action}${l.details ? `\n   Details: ${l.details}` : ''}`).join('\n')}

================================================================================
RECOMMENDATIONS
================================================================================
1. Implement email attachment sandboxing
2. Enable PowerShell script block logging
3. Increase backup frequency to hourly
4. Conduct phishing awareness training
5. Review and tighten RDP access policies

================================================================================
                              END OF REPORT
================================================================================
    `;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Detailed incident report exported');
  };

  const filteredLogs = logs.filter(log => {
    if (logFilter !== 'all' && log.severity !== logFilter) return false;
    if (searchQuery && !log.action.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const getAssetIcon = (type: Asset['type']) => {
    switch (type) {
      case 'workstation': return Terminal;
      case 'server': return Server;
      case 'network': return Wifi;
      case 'database': return Database;
    }
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-primary text-glow-cyan tracking-wider flex items-center gap-3">
          <ClipboardList className="w-8 h-8" />
          INCIDENT RESPONSE
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Real-time SIEM-style incident response simulation
        </p>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-4 mb-6">
        <Button
          variant="cyber"
          size="lg"
          onClick={runIncidentResponse}
          disabled={isRunning && !isPaused}
        >
          {isRunning && !isPaused ? (
            <>
              <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
              RESPONDING...
            </>
          ) : isPaused ? (
            <>
              <Play className="w-5 h-5" />
              RESUME
            </>
          ) : (
            <>
              <AlertTriangle className="w-5 h-5" />
              START INCIDENT RESPONSE
            </>
          )}
        </Button>
        {isRunning && !isPaused && (
          <Button variant="outline" onClick={pauseWorkflow}>
            <Pause className="w-4 h-4 mr-2" />
            Pause
          </Button>
        )}
        <Button variant="outline" onClick={resetWorkflow} disabled={isRunning && !isPaused}>
          <RotateCcw className="w-4 h-4 mr-2" />
          Reset
        </Button>
        <Button variant="outline" onClick={exportReport} disabled={logs.length === 0}>
          <Download className="w-4 h-4 mr-2" />
          Export Report
        </Button>
      </div>

      {/* Asset Status Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
        {assets.map(asset => {
          const Icon = getAssetIcon(asset.type);
          return (
            <div
              key={asset.id}
              className={cn(
                "cyber-card p-3 border transition-all",
                asset.status === 'healthy' && "border-border",
                asset.status === 'infected' && "border-destructive bg-destructive/10 animate-pulse",
                asset.status === 'isolated' && "border-warning bg-warning/10",
                asset.status === 'recovered' && "border-success bg-success/10"
              )}
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className={cn(
                  "w-4 h-4",
                  asset.status === 'healthy' && "text-muted-foreground",
                  asset.status === 'infected' && "text-destructive",
                  asset.status === 'isolated' && "text-warning",
                  asset.status === 'recovered' && "text-success"
                )} />
                <span className="font-mono text-xs truncate">{asset.name}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground font-mono">{asset.ip}</span>
                <span className={cn(
                  "text-xs font-mono px-1.5 py-0.5 rounded",
                  asset.status === 'healthy' && "text-muted-foreground bg-muted",
                  asset.status === 'infected' && "text-destructive bg-destructive/20",
                  asset.status === 'isolated' && "text-warning bg-warning/20",
                  asset.status === 'recovered' && "text-success bg-success/20"
                )}>
                  {asset.status === 'healthy' ? '●' : asset.status === 'infected' ? '!' : asset.status === 'isolated' ? '⊘' : '✓'}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Workflow Steps */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              RESPONSE PHASES
            </h3>
            <div className="space-y-3">
              {steps.map((step, idx) => (
                <div
                  key={step.id}
                  className={cn(
                    "p-4 rounded-lg border transition-all duration-300",
                    step.status === 'pending' && "bg-secondary/30 border-border/50",
                    step.status === 'in-progress' && "bg-warning/10 border-warning/50",
                    step.status === 'completed' && "bg-success/10 border-success/30"
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0 mt-1">
                      {step.status === 'pending' && <Circle className="w-5 h-5 text-muted-foreground" />}
                      {step.status === 'in-progress' && (
                        <div className="w-5 h-5 border-2 border-warning border-t-transparent rounded-full animate-spin" />
                      )}
                      {step.status === 'completed' && <CheckCircle className="w-5 h-5 text-success" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <h4 className="font-display font-bold text-sm text-foreground">{step.title}</h4>
                        <span className={cn(
                          "text-xs font-mono px-2 py-0.5 rounded flex-shrink-0",
                          step.status === 'pending' && "text-muted-foreground bg-muted",
                          step.status === 'in-progress' && "text-warning bg-warning/20",
                          step.status === 'completed' && "text-success bg-success/20"
                        )}>
                          {idx + 1}/5
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono mt-1">{step.description}</p>
                      {step.timestamp && (
                        <p className="text-xs text-muted-foreground font-mono mt-2 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {step.timestamp.toLocaleTimeString()}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Activity Log */}
        <div className="lg:col-span-2 cyber-card p-5 border border-border">
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider flex items-center gap-2">
                <FileText className="w-5 h-5 text-primary" />
                SIEM ACTIVITY LOG
              </h3>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-4 h-4 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search logs..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-8 pr-3 py-1 text-xs font-mono bg-secondary/50 border border-border rounded focus:outline-none focus:border-primary w-32"
                  />
                </div>
                <select
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                  className="text-xs font-mono bg-secondary/50 border border-border rounded px-2 py-1 focus:outline-none focus:border-primary"
                >
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="warning">Warning</option>
                  <option value="success">Success</option>
                  <option value="info">Info</option>
                </select>
              </div>
            </div>
            
            <div ref={logContainerRef} className="space-y-1.5 max-h-[500px] overflow-y-auto font-mono text-xs">
              {filteredLogs.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Activity className="w-12 h-12 text-muted-foreground/30 mb-3" />
                  <p className="text-muted-foreground">
                    {logs.length === 0 ? 'Start incident response to see activity log' : 'No logs match your filter'}
                  </p>
                </div>
              ) : (
                filteredLogs.map((log) => (
                  <div
                    key={log.id}
                    className={cn(
                      "p-2 rounded border animate-fade-in",
                      log.severity === 'info' && "bg-primary/5 border-primary/20",
                      log.severity === 'warning' && "bg-warning/10 border-warning/30",
                      log.severity === 'critical' && "bg-destructive/10 border-destructive/30",
                      log.severity === 'success' && "bg-success/10 border-success/30"
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <span className={cn(
                        "text-xs px-1.5 py-0.5 rounded flex-shrink-0",
                        log.severity === 'info' && "bg-primary/20 text-primary",
                        log.severity === 'warning' && "bg-warning/20 text-warning",
                        log.severity === 'critical' && "bg-destructive/20 text-destructive",
                        log.severity === 'success' && "bg-success/20 text-success"
                      )}>
                        {log.severity.slice(0, 4).toUpperCase()}
                      </span>
                      <span className="text-muted-foreground flex-shrink-0">
                        [{log.timestamp.toLocaleTimeString()}]
                      </span>
                      <span className="text-primary flex-shrink-0">[{log.source}]</span>
                      <span className="text-foreground flex-1">{log.action}</span>
                    </div>
                    {log.details && (
                      <div className="mt-1 pl-6 text-muted-foreground text-xs italic">
                        {log.details}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Threat Indicators */}
      {indicators.length > 0 && (
        <div className="mt-6 cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <Bug className="w-5 h-5 text-destructive" />
              INDICATORS OF COMPROMISE (IOCs)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {indicators.map((ioc) => (
                <div
                  key={ioc.id}
                  className="p-3 rounded-lg border border-destructive/30 bg-destructive/5"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-destructive/20 text-destructive uppercase">
                      {ioc.type}
                    </span>
                    <span className={cn(
                      "text-xs font-mono",
                      ioc.confidence === 'high' && "text-destructive",
                      ioc.confidence === 'medium' && "text-warning",
                      ioc.confidence === 'low' && "text-muted-foreground"
                    )}>
                      {ioc.confidence} confidence
                    </span>
                  </div>
                  <p className="font-mono text-xs text-foreground break-all">{ioc.value}</p>
                  <p className="text-xs text-muted-foreground mt-1">Source: {ioc.source}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default IncidentPage;