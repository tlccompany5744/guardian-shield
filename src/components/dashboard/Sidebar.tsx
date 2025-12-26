import { NavLink } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import CyberLogo from '@/components/CyberLogo';
import { Button } from '@/components/ui/button';
import {
  Shield,
  Lock,
  Unlock,
  AlertTriangle,
  Activity,
  BookOpen,
  MessageSquare,
  LogOut,
  ChevronLeft,
  ChevronRight,
  FileKey,
  Search,
  ClipboardList,
  Fish,
  Radar,
} from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/lib/utils';

const menuItems = [
  { icon: Activity, label: 'Dashboard', path: '/' },
  { icon: Lock, label: 'Encrypt Simulation', path: '/encrypt' },
  { icon: Unlock, label: 'Decrypt & Recover', path: '/decrypt' },
  { icon: AlertTriangle, label: 'Detection Monitor', path: '/detection' },
  { icon: ClipboardList, label: 'Incident Response', path: '/incident' },
  { icon: Fish, label: 'Phishing Simulator', path: '/phishing-simulator' },
  { icon: Radar, label: 'Port Scanner', path: '/port-scanner' },
  { icon: MessageSquare, label: 'AI Assistant', path: '/assistant' },
  { icon: Search, label: 'Threat Intel', path: '/threat-intel' },
  { icon: BookOpen, label: 'Learning Lab', path: '/learning' },
];

const Sidebar = () => {
  const { signOut, user } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "h-screen bg-sidebar border-r border-sidebar-border flex flex-col transition-all duration-300",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Logo */}
      <div className="p-4 border-b border-sidebar-border flex items-center justify-between">
        <CyberLogo size="sm" showText={!collapsed} />
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-2 text-muted-foreground hover:text-primary transition-colors"
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
        {menuItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group",
                isActive
                  ? "bg-primary/10 text-primary border border-primary/30 shadow-[0_0_10px_hsl(var(--primary)/0.2)]"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary"
              )
            }
          >
            <item.icon className={cn("w-5 h-5 flex-shrink-0", collapsed && "mx-auto")} />
            {!collapsed && (
              <span className="font-mono text-sm truncate">{item.label}</span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User Section */}
      <div className="p-4 border-t border-sidebar-border space-y-3">
        {!collapsed && user && (
          <div className="flex items-center gap-2 px-2">
            <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
              <Shield className="w-4 h-4 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-muted-foreground font-mono">Operator</p>
              <p className="text-sm font-mono truncate text-foreground">{user.email}</p>
            </div>
          </div>
        )}
        <Button
          variant="ghost"
          onClick={signOut}
          className={cn(
            "w-full text-muted-foreground hover:text-destructive hover:bg-destructive/10",
            collapsed ? "justify-center" : "justify-start"
          )}
        >
          <LogOut className="w-4 h-4" />
          {!collapsed && <span className="font-mono text-sm ml-2">Logout</span>}
        </Button>
      </div>
    </aside>
  );
};

export default Sidebar;
