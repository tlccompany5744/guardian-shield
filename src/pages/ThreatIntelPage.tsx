import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Search, Globe, AlertTriangle, Shield, ExternalLink, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface ThreatInfo {
  id: string;
  name: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  indicators: string[];
  mitigation: string;
}

const threatDatabase: ThreatInfo[] = [
  {
    id: '1',
    name: 'WannaCry',
    type: 'Ransomware',
    severity: 'critical',
    description: 'WannaCry is a ransomware cryptoworm that targets Windows machines by exploiting the EternalBlue vulnerability in SMB protocol.',
    indicators: ['Encrypted files with .WCRY extension', 'Ransom note in multiple languages', 'SMB exploitation attempts'],
    mitigation: 'Patch MS17-010, disable SMBv1, maintain offline backups, use network segmentation'
  },
  {
    id: '2',
    name: 'Ryuk',
    type: 'Ransomware',
    severity: 'critical',
    description: 'Ryuk is a sophisticated ransomware targeting large enterprises. It often follows TrickBot or Emotet infections.',
    indicators: ['Encrypted files with .RYK extension', 'RyukReadMe.txt ransom note', 'Process injection techniques'],
    mitigation: 'Email filtering, endpoint protection, network monitoring, regular backups'
  },
  {
    id: '3',
    name: 'LockBit',
    type: 'Ransomware-as-a-Service',
    severity: 'high',
    description: 'LockBit is a RaaS operation known for fast encryption and double extortion tactics.',
    indicators: ['Rapid file encryption', 'Data exfiltration before encryption', 'Affiliate-based attacks'],
    mitigation: 'Implement MFA, monitor for lateral movement, secure RDP, maintain offline backups'
  },
  {
    id: '4',
    name: 'Conti',
    type: 'Ransomware',
    severity: 'critical',
    description: 'Conti ransomware uses manual hacking and multi-threaded encryption for rapid deployment.',
    indicators: ['CONTI extension on files', 'Cobalt Strike beacons', 'Active Directory compromise'],
    mitigation: 'Privileged access management, network segmentation, endpoint detection and response'
  },
  {
    id: '5',
    name: 'REvil/Sodinokibi',
    type: 'Ransomware-as-a-Service',
    severity: 'high',
    description: 'REvil was one of the most prolific RaaS operations, targeting high-value organizations.',
    indicators: ['Random file extensions', 'Wallpaper change after encryption', 'Tor payment site'],
    mitigation: 'Vulnerability management, application whitelisting, incident response planning'
  }
];

const ThreatIntelPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [results, setResults] = useState<ThreatInfo[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<ThreatInfo | null>(null);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  const searchThreats = async () => {
    if (!searchQuery.trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setIsSearching(true);
    setResults([]);
    setSelectedThreat(null);

    // Simulate search delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    const filtered = threatDatabase.filter(threat =>
      threat.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      threat.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      threat.description.toLowerCase().includes(searchQuery.toLowerCase())
    );

    setResults(filtered);
    setIsSearching(false);

    if (filtered.length === 0) {
      toast.info('No threats found matching your query');
    } else {
      toast.success(`Found ${filtered.length} threat(s)`);
    }
  };

  const severityColors = {
    low: 'text-success bg-success/10 border-success/30',
    medium: 'text-primary bg-primary/10 border-primary/30',
    high: 'text-warning bg-warning/10 border-warning/30',
    critical: 'text-destructive bg-destructive/10 border-destructive/30'
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-primary text-glow-cyan tracking-wider flex items-center gap-3">
          <Globe className="w-8 h-8" />
          THREAT INTELLIGENCE
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Search and analyze known ransomware threats and indicators of compromise
        </p>
      </div>

      {/* Search Bar */}
      <div className="cyber-card p-4 border border-border mb-6">
        <div className="relative z-10 flex gap-4">
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && searchThreats()}
            placeholder="Search threats (e.g., WannaCry, Ryuk, LockBit)..."
            className="flex-1 font-mono"
          />
          <Button variant="cyber" onClick={searchThreats} disabled={isSearching}>
            {isSearching ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            SEARCH
          </Button>
        </div>

        {/* Quick Tags */}
        <div className="flex flex-wrap gap-2 mt-4">
          {['ransomware', 'WannaCry', 'RaaS', 'Ryuk', 'LockBit'].map(tag => (
            <button
              key={tag}
              onClick={() => {
                setSearchQuery(tag);
              }}
              className="px-3 py-1 text-xs font-mono bg-secondary/50 rounded-full hover:bg-primary/20 hover:text-primary transition-colors"
            >
              {tag}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Results List */}
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10">
            <h3 className="font-display font-bold text-foreground mb-4">
              SEARCH RESULTS
            </h3>
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {results.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  {isSearching ? 'Searching...' : 'Enter a query to search threat database'}
                </p>
              ) : (
                results.map(threat => (
                  <button
                    key={threat.id}
                    onClick={() => setSelectedThreat(threat)}
                    className={cn(
                      "w-full text-left p-3 rounded-lg border transition-all",
                      selectedThreat?.id === threat.id
                        ? "bg-primary/10 border-primary"
                        : "bg-secondary/30 border-border/50 hover:border-primary/50"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-foreground">{threat.name}</span>
                      <span className={cn(
                        "text-xs px-2 py-0.5 rounded border",
                        severityColors[threat.severity]
                      )}>
                        {threat.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground font-mono mt-1">{threat.type}</p>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Threat Details */}
        <div className="lg:col-span-2 cyber-card p-5 border border-border">
          <div className="relative z-10">
            {selectedThreat ? (
              <>
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="font-display text-2xl font-bold text-foreground">{selectedThreat.name}</h2>
                    <p className="text-sm text-muted-foreground font-mono">{selectedThreat.type}</p>
                  </div>
                  <span className={cn(
                    "px-3 py-1 rounded border text-sm font-mono",
                    severityColors[selectedThreat.severity]
                  )}>
                    {selectedThreat.severity.toUpperCase()} SEVERITY
                  </span>
                </div>

                <div className="space-y-6">
                  <div>
                    <h4 className="font-display font-bold text-foreground mb-2 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-warning" />
                      DESCRIPTION
                    </h4>
                    <p className="text-sm text-muted-foreground font-mono">{selectedThreat.description}</p>
                  </div>

                  <div>
                    <h4 className="font-display font-bold text-foreground mb-2">INDICATORS OF COMPROMISE</h4>
                    <ul className="space-y-2">
                      {selectedThreat.indicators.map((ioc, idx) => (
                        <li key={idx} className="text-sm font-mono text-foreground flex items-center gap-2">
                          <div className="w-1.5 h-1.5 rounded-full bg-destructive" />
                          {ioc}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-display font-bold text-foreground mb-2 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-success" />
                      MITIGATION
                    </h4>
                    <p className="text-sm text-muted-foreground font-mono">{selectedThreat.mitigation}</p>
                  </div>

                  <div className="pt-4 border-t border-border">
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => {
                        toast.info(`Full report for ${selectedThreat.name}`, {
                          description: `Threat Type: ${selectedThreat.type} | Severity: ${selectedThreat.severity.toUpperCase()}. This is a simulation database - in production, this would link to MITRE ATT&CK or similar threat intelligence sources.`,
                          duration: 8000,
                        });
                      }}
                    >
                      <ExternalLink className="w-4 h-4 mr-2" />
                      View Full Report
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 text-center">
                <Globe className="w-16 h-16 text-primary/30 mb-4" />
                <h3 className="font-display text-xl text-foreground mb-2">Threat Intelligence Database</h3>
                <p className="text-muted-foreground font-mono text-sm max-w-md">
                  Search for known ransomware threats to view detailed analysis, indicators of compromise, and mitigation strategies.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ThreatIntelPage;
