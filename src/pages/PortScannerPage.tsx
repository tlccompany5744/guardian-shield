import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { 
  Radar, 
  Play, 
  Square, 
  Download,
  AlertTriangle,
  Shield,
  Wifi,
  WifiOff,
  Server,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  History
} from "lucide-react";

interface PortResult {
  port: number;
  status: "open" | "closed" | "filtered";
  service?: string;
  responseTime?: number;
}

interface ScanHistory {
  id: string;
  target_host: string;
  start_port: number;
  end_port: number;
  status: string;
  results: PortResult[];
  created_at: string;
  completed_at: string | null;
}

// Common port presets
const portPresets = [
  { name: "Web Ports", start: 80, end: 443 },
  { name: "Common Services", start: 20, end: 25 },
  { name: "Database Ports", start: 3306, end: 3306 },
  { name: "Full Common", start: 1, end: 100 },
];

export default function PortScannerPage() {
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [host, setHost] = useState("");
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort] = useState(100);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<PortResult[]>([]);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    if (!authLoading && !user) {
      navigate("/auth");
    }
  }, [user, authLoading, navigate]);

  useEffect(() => {
    if (user) {
      fetchScanHistory();
    }
  }, [user]);

  // Subscribe to realtime updates for current scan
  useEffect(() => {
    if (!currentScanId) return;

    const channel = supabase
      .channel(`scan-${currentScanId}`)
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'port_scans',
          filter: `id=eq.${currentScanId}`
        },
        (payload: any) => {
          const scan = payload.new as ScanHistory;
          if (scan.results) {
            setResults(scan.results);
            const totalPorts = endPort - startPort + 1;
            setProgress(Math.round((scan.results.length / totalPorts) * 100));
          }
          if (scan.status === "completed") {
            setIsScanning(false);
            setProgress(100);
            toast({ title: "Scan complete", description: `Found ${scan.results?.filter((r: PortResult) => r.status === "open").length || 0} open ports` });
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [currentScanId, startPort, endPort, toast]);

  const fetchScanHistory = async () => {
    const { data, error } = await supabase
      .from("port_scans")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(10);

    if (!error && data) {
      setScanHistory(data.map((d: any) => ({
        ...d,
        results: (d.results || []) as PortResult[]
      })));
    }
  };

  const startScan = async () => {
    if (!host) {
      toast({ title: "Missing host", description: "Please enter a target host", variant: "destructive" });
      return;
    }

    if (endPort - startPort > 100) {
      toast({ title: "Port range too large", description: "Maximum 100 ports per scan", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setProgress(0);
    setResults([]);

    try {
      const { data, error } = await supabase.functions.invoke("port-scanner", {
        body: { host, startPort, endPort }
      });

      if (error) throw error;

      setCurrentScanId(data.scanId);
      setResults(data.results || []);
      setProgress(100);
      setIsScanning(false);
      
      toast({ 
        title: "Scan complete", 
        description: `Found ${data.results?.filter((r: PortResult) => r.status === "open").length || 0} open ports` 
      });

      fetchScanHistory();
    } catch (error: any) {
      console.error("Scan error:", error);
      setIsScanning(false);
      toast({ title: "Scan failed", description: error.message, variant: "destructive" });
    }
  };

  const stopScan = () => {
    setIsScanning(false);
    toast({ title: "Scan stopped" });
  };

  const exportResults = () => {
    const openPorts = results.filter(r => r.status === "open");
    const report = {
      host,
      scanDate: new Date().toISOString(),
      portRange: `${startPort}-${endPort}`,
      summary: {
        total: results.length,
        open: openPorts.length,
        closed: results.filter(r => r.status === "closed").length,
        filtered: results.filter(r => r.status === "filtered").length,
      },
      openPorts: openPorts.map(p => ({
        port: p.port,
        service: p.service || "unknown",
        responseTime: p.responseTime ? `${p.responseTime}ms` : "N/A",
      })),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `port-scan-${host}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const loadHistoryScan = (scan: ScanHistory) => {
    setHost(scan.target_host);
    setStartPort(scan.start_port);
    setEndPort(scan.end_port);
    setResults(scan.results || []);
    setShowHistory(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open": return "text-green-500";
      case "closed": return "text-red-500";
      case "filtered": return "text-yellow-500";
      default: return "text-muted-foreground";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "open": return <Wifi className="w-4 h-4 text-green-500" />;
      case "closed": return <WifiOff className="w-4 h-4 text-red-500" />;
      case "filtered": return <Shield className="w-4 h-4 text-yellow-500" />;
      default: return <Server className="w-4 h-4" />;
    }
  };

  // Statistics
  const openPorts = results.filter(r => r.status === "open");
  const closedPorts = results.filter(r => r.status === "closed");
  const filteredPorts = results.filter(r => r.status === "filtered");

  if (authLoading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Radar className="w-8 h-8 text-primary animate-pulse" />
              Defensive Port Scanner
            </h1>
            <p className="text-muted-foreground mt-1">
              TCP connect scan for security assessment (authorized use only)
            </p>
          </div>
          <Button variant="outline" onClick={() => setShowHistory(!showHistory)}>
            <History className="w-4 h-4 mr-2" />
            Scan History
          </Button>
        </div>

        {/* Warning Banner */}
        <Card className="border-warning bg-warning/10">
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-6 h-6 text-warning" />
              <div>
                <p className="font-medium">⚠️ Legal Notice</p>
                <p className="text-sm text-muted-foreground">
                  Only scan systems you own or have explicit authorization to test. 
                  Unauthorized port scanning may violate computer crime laws.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scan Configuration */}
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle>Scan Configuration</CardTitle>
              <CardDescription>Configure your port scan parameters</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium">Target Host / IP</label>
                <Input
                  placeholder="example.com or 192.168.1.1"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  disabled={isScanning}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium">Start Port</label>
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    value={startPort}
                    onChange={(e) => setStartPort(parseInt(e.target.value) || 1)}
                    disabled={isScanning}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">End Port</label>
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    value={endPort}
                    onChange={(e) => setEndPort(parseInt(e.target.value) || 100)}
                    disabled={isScanning}
                  />
                </div>
              </div>

              <div>
                <label className="text-sm font-medium">Quick Presets</label>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  {portPresets.map((preset) => (
                    <Button
                      key={preset.name}
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setStartPort(preset.start);
                        setEndPort(preset.end);
                      }}
                      disabled={isScanning}
                    >
                      {preset.name}
                    </Button>
                  ))}
                </div>
              </div>

              {isScanning ? (
                <Button 
                  onClick={stopScan} 
                  variant="destructive"
                  className="w-full"
                >
                  <Square className="w-4 h-4 mr-2" />
                  Stop Scan
                </Button>
              ) : (
                <Button 
                  onClick={startScan} 
                  variant="cyber"
                  className="w-full"
                  disabled={!host}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Start Scan
                </Button>
              )}

              {isScanning && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Scanning...
                    </span>
                    <span>{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}

              {results.length > 0 && (
                <Button 
                  onClick={exportResults} 
                  variant="outline"
                  className="w-full"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export Report
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Results */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Scan Results</span>
                {results.length > 0 && (
                  <div className="flex items-center gap-4 text-sm font-normal">
                    <span className="flex items-center gap-1">
                      <CheckCircle2 className="w-4 h-4 text-green-500" />
                      {openPorts.length} Open
                    </span>
                    <span className="flex items-center gap-1">
                      <XCircle className="w-4 h-4 text-red-500" />
                      {closedPorts.length} Closed
                    </span>
                    <span className="flex items-center gap-1">
                      <Shield className="w-4 h-4 text-yellow-500" />
                      {filteredPorts.length} Filtered
                    </span>
                  </div>
                )}
              </CardTitle>
              <CardDescription>
                {results.length > 0 
                  ? `Scanned ${results.length} ports on ${host}`
                  : "Results will appear here after scan completes"
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {results.length === 0 && !isScanning ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Radar className="w-16 h-16 mx-auto mb-4 opacity-50" />
                  <p>No scan results yet</p>
                  <p className="text-sm">Configure your target and click "Start Scan"</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Open Ports Summary */}
                  {openPorts.length > 0 && (
                    <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                      <h3 className="font-medium text-green-500 mb-3 flex items-center gap-2">
                        <Wifi className="w-5 h-5" />
                        Open Ports ({openPorts.length})
                      </h3>
                      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                        {openPorts.map((port) => (
                          <div
                            key={port.port}
                            className="bg-background rounded p-2 border"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-green-500">
                                {port.port}
                              </span>
                              {port.responseTime && (
                                <span className="text-xs text-muted-foreground">
                                  {port.responseTime}ms
                                </span>
                              )}
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {port.service || "unknown"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* All Results Table */}
                  <div className="max-h-[400px] overflow-auto">
                    <table className="w-full">
                      <thead className="sticky top-0 bg-background">
                        <tr className="border-b">
                          <th className="text-left p-2">Port</th>
                          <th className="text-left p-2">Status</th>
                          <th className="text-left p-2">Service</th>
                          <th className="text-left p-2">Response</th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.map((result) => (
                          <tr key={result.port} className="border-b border-border/50 hover:bg-muted/50">
                            <td className="p-2 font-mono">{result.port}</td>
                            <td className="p-2">
                              <div className="flex items-center gap-2">
                                {getStatusIcon(result.status)}
                                <span className={getStatusColor(result.status)}>
                                  {result.status.toUpperCase()}
                                </span>
                              </div>
                            </td>
                            <td className="p-2 text-muted-foreground">
                              {result.service || "-"}
                            </td>
                            <td className="p-2 text-muted-foreground">
                              {result.responseTime ? `${result.responseTime}ms` : "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Scan History */}
        {showHistory && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <History className="w-5 h-5" />
                Recent Scans
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {scanHistory.length === 0 ? (
                  <p className="text-muted-foreground text-center py-4">No scan history yet</p>
                ) : (
                  scanHistory.map((scan) => (
                    <div
                      key={scan.id}
                      onClick={() => loadHistoryScan(scan)}
                      className="flex items-center justify-between p-3 rounded-lg border hover:bg-muted/50 cursor-pointer"
                    >
                      <div>
                        <p className="font-medium">{scan.target_host}</p>
                        <p className="text-sm text-muted-foreground">
                          Ports {scan.start_port}-{scan.end_port}
                        </p>
                      </div>
                      <div className="text-right">
                        <Badge variant={scan.status === "completed" ? "default" : "secondary"}>
                          {scan.status}
                        </Badge>
                        <p className="text-xs text-muted-foreground mt-1">
                          {new Date(scan.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
}
