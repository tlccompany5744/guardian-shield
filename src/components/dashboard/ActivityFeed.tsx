import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Lock, Unlock, FileWarning } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Activity {
  id: string;
  type: 'encrypt' | 'decrypt' | 'detect' | 'alert' | 'recovery';
  message: string;
  timestamp: Date;
}

const iconMap = {
  encrypt: Lock,
  decrypt: Unlock,
  detect: Shield,
  alert: AlertTriangle,
  recovery: CheckCircle,
};

const colorMap = {
  encrypt: 'text-destructive',
  decrypt: 'text-success',
  detect: 'text-primary',
  alert: 'text-warning',
  recovery: 'text-accent',
};

const initialActivities: Activity[] = [
  { id: '1', type: 'detect', message: 'System monitoring initialized', timestamp: new Date() },
  { id: '2', type: 'alert', message: 'Behavioral analysis engine active', timestamp: new Date(Date.now() - 60000) },
  { id: '3', type: 'recovery', message: 'Backup systems verified', timestamp: new Date(Date.now() - 120000) },
];

const ActivityFeed = () => {
  const [activities, setActivities] = useState<Activity[]>(initialActivities);

  useEffect(() => {
    const messages = [
      { type: 'detect' as const, message: 'File system scan completed' },
      { type: 'alert' as const, message: 'Monitoring network traffic' },
      { type: 'recovery' as const, message: 'Shadow copies verified' },
      { type: 'detect' as const, message: 'Process monitoring active' },
    ];

    const interval = setInterval(() => {
      const newActivity = {
        id: Date.now().toString(),
        ...messages[Math.floor(Math.random() * messages.length)],
        timestamp: new Date(),
      };
      
      setActivities((prev) => [newActivity, ...prev.slice(0, 9)]);
    }, 8000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="cyber-card p-5 border border-border">
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display text-lg font-bold text-foreground tracking-wider">ACTIVITY FEED</h3>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full status-online" />
            <span className="text-xs font-mono text-success">LIVE</span>
          </div>
        </div>

        <div className="space-y-3 max-h-80 overflow-y-auto">
          {activities.map((activity, index) => {
            const Icon = iconMap[activity.type];
            return (
              <div
                key={activity.id}
                className={cn(
                  "flex items-start gap-3 p-3 rounded-lg bg-secondary/30 border border-border/50 transition-all duration-300",
                  index === 0 && "animate-fade-in border-primary/30"
                )}
              >
                <div className={cn("p-1.5 rounded", colorMap[activity.type], "bg-current/10")}>
                  <Icon className={cn("w-4 h-4", colorMap[activity.type])} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-mono text-foreground truncate">{activity.message}</p>
                  <p className="text-xs text-muted-foreground font-mono">
                    {activity.timestamp.toLocaleTimeString()}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ActivityFeed;
