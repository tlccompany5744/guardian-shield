import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: string;
  variant?: 'default' | 'success' | 'warning' | 'danger';
}

const StatCard = ({ title, value, icon: Icon, trend, trendValue, variant = 'default' }: StatCardProps) => {
  const variantStyles = {
    default: 'border-border hover:border-primary/50',
    success: 'border-success/30 hover:border-success',
    warning: 'border-warning/30 hover:border-warning',
    danger: 'border-destructive/30 hover:border-destructive animate-pulse-slow',
  };

  const iconStyles = {
    default: 'text-primary bg-primary/10',
    success: 'text-success bg-success/10',
    warning: 'text-warning bg-warning/10',
    danger: 'text-destructive bg-destructive/10',
  };

  return (
    <div className={cn(
      "cyber-card p-5 border transition-all duration-300 hover:shadow-lg group",
      variantStyles[variant]
    )}>
      <div className="relative z-10 flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="text-2xl font-display font-bold text-foreground">{value}</p>
          {trendValue && (
            <p className={cn(
              "text-xs font-mono",
              trend === 'up' && 'text-success',
              trend === 'down' && 'text-destructive',
              trend === 'neutral' && 'text-muted-foreground'
            )}>
              {trendValue}
            </p>
          )}
        </div>
        <div className={cn(
          "p-3 rounded-lg transition-all duration-300 group-hover:scale-110",
          iconStyles[variant]
        )}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
};

export default StatCard;
