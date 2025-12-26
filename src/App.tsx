import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "@/hooks/useAuth";
import Index from "./pages/Index";
import Auth from "./pages/Auth";
import EncryptPage from "./pages/EncryptPage";
import DecryptPage from "./pages/DecryptPage";
import DetectionPage from "./pages/DetectionPage";
import IncidentPage from "./pages/IncidentPage";
import AssistantPage from "./pages/AssistantPage";
import ThreatIntelPage from "./pages/ThreatIntelPage";
import LearningPage from "./pages/LearningPage";
import PhishingSimulatorPage from "./pages/PhishingSimulatorPage";
import PortScannerPage from "./pages/PortScannerPage";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/auth" element={<Auth />} />
            <Route path="/encrypt" element={<EncryptPage />} />
            <Route path="/decrypt" element={<DecryptPage />} />
            <Route path="/detection" element={<DetectionPage />} />
            <Route path="/incident" element={<IncidentPage />} />
            <Route path="/assistant" element={<AssistantPage />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/learning" element={<LearningPage />} />
            <Route path="/phishing-simulator" element={<PhishingSimulatorPage />} />
            <Route path="/port-scanner" element={<PortScannerPage />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
