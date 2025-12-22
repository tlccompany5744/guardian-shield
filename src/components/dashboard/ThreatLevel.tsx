import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, AlertOctagon, CheckCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

type ThreatLevelType = 'low' | 'medium' | 'high' | 'critical';

interface ThreatConfig {
  label: string;
  color: string;
  bgColor: string;
  icon: typeof Shield;
  description: string;
}

const threatConfigs: Record<ThreatLevelType, ThreatConfig> = {
  low: {
    label: 'LOW',
    color: 'text-success',
    bgColor: 'bg-success/20',
    icon: CheckCircle,
    description: 'No active threats detected',
  },
  medium: {
    label: 'MEDIUM',
    color: 'text-primary',
    bgColor: 'bg-primary/20',
    icon: Shield,
    description: 'Standard monitoring active',
  },
  high: {
    label: 'HIGH',
    color: 'text-warning',
    bgColor: 'bg-warning/20',
    icon: AlertTriangle,
    description: 'Elevated activity detected',
  },
  critical: {
    label: 'CRITICAL',
    color: 'text-destructive',
    bgColor: 'bg-destructive/20',
    icon: AlertOctagon,
    description: 'Immediate action required',
  },
};

const ThreatLevel = () => {
  const [level, setLevel] = useState<ThreatLevelType>('low');
  const config = threatConfigs[level];
  const Icon = config.icon;

  // Simulate threat level changes
  useEffect(() => {
    const levels: ThreatLevelType[] = ['low', 'medium', 'low', 'low'];
    let index = 0;

    const interval = setInterval(() => {
      index = (index + 1) % levels.length;
      setLevel(levels[index]);
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="cyber-card p-5 border border-border">
      <div className="relative z-10">
        <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
          THREAT LEVEL
        </h3>

        <div className="flex items-center gap-4">
          <div className={cn(
            "p-4 rounded-xl transition-all duration-500",
            config.bgColor,
            level === 'critical' && 'animate-pulse'
          )}>
            <Icon className={cn("w-10 h-10", config.color)} />
          </div>

          <div className="flex-1">
            <p className={cn(
              "font-display text-2xl font-bold tracking-widest",
              config.color
            )}>
              {config.label}
            </p>
            <p className="text-sm text-muted-foreground font-mono mt-1">
              {config.description}
            </p>
          </div>
        </div>

        {/* Threat meter */}
        <div className="mt-4">
          <div className="flex justify-between text-xs font-mono text-muted-foreground mb-2">
            <span>LOW</span>
            <span>CRITICAL</span>
          </div>
          <div className="h-2 bg-muted rounded-full overflow-hidden">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500",
                level === 'low' && 'w-1/4 bg-success',
                level === 'medium' && 'w-1/2 bg-primary',
                level === 'high' && 'w-3/4 bg-warning',
                level === 'critical' && 'w-full bg-destructive animate-pulse'
              )}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatLevel;
