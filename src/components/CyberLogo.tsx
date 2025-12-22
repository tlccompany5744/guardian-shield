import { Shield, Lock } from 'lucide-react';

interface CyberLogoProps {
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
}

const CyberLogo = ({ size = 'md', showText = true }: CyberLogoProps) => {
  const sizeClasses = {
    sm: 'w-8 h-8',
    md: 'w-12 h-12',
    lg: 'w-16 h-16',
  };

  const textSizes = {
    sm: 'text-lg',
    md: 'text-2xl',
    lg: 'text-3xl',
  };

  return (
    <div className="flex items-center gap-3">
      <div className={`relative ${sizeClasses[size]}`}>
        <div className="absolute inset-0 bg-primary/20 rounded-lg blur-lg animate-pulse" />
        <div className="relative bg-gradient-to-br from-primary to-accent p-2 rounded-lg shadow-[0_0_20px_hsl(var(--primary)/0.5)]">
          <Shield className="w-full h-full text-primary-foreground" strokeWidth={1.5} />
          <Lock className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-1/2 h-1/2 text-primary-foreground" strokeWidth={2} />
        </div>
      </div>
      {showText && (
        <div className="flex flex-col">
          <span className={`font-display font-bold ${textSizes[size]} text-primary text-glow-cyan tracking-wider`}>
            CYBERGUARD
          </span>
          <span className="text-xs text-muted-foreground font-mono tracking-widest uppercase">
            Ransomware Defense Lab
          </span>
        </div>
      )}
    </div>
  );
};

export default CyberLogo;
