import { ReactNode } from 'react';
import Sidebar from './Sidebar';
import MatrixRain from '../MatrixRain';

interface DashboardLayoutProps {
  children: ReactNode;
}

const DashboardLayout = ({ children }: DashboardLayoutProps) => {
  return (
    <div className="flex min-h-screen bg-background">
      <MatrixRain />
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <div className="relative min-h-full">
          {/* Grid background */}
          <div className="absolute inset-0 grid-bg opacity-30 pointer-events-none" />
          
          {/* Content */}
          <div className="relative z-10 p-6">
            {children}
          </div>
        </div>
      </main>
    </div>
  );
};

export default DashboardLayout;
