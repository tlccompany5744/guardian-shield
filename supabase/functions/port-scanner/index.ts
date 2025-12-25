import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ScanRequest {
  host: string;
  startPort: number;
  endPort: number;
  scanId?: string;
}

interface PortResult {
  port: number;
  status: "open" | "closed" | "filtered";
  service?: string;
  responseTime?: number;
}

// Common port to service mapping
const commonPorts: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  27017: "MongoDB",
};

async function scanPort(host: string, port: number, timeout = 3000): Promise<PortResult> {
  const startTime = Date.now();
  
  try {
    // Use HTTP/HTTPS probe for web ports
    const protocol = [443, 8443, 993, 995].includes(port) ? "https" : "http";
    const url = `${protocol}://${host}:${port}`;
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url, {
        method: "HEAD",
        signal: controller.signal,
        // @ts-ignore - Deno specific
        redirect: "manual",
      });
      
      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;
      
      return {
        port,
        status: "open",
        service: commonPorts[port] || "unknown",
        responseTime,
      };
    } catch (fetchError: any) {
      clearTimeout(timeoutId);
      
      // Connection refused means port is closed
      if (fetchError.message?.includes("Connection refused")) {
        return { port, status: "closed" };
      }
      
      // Timeout or abort means filtered
      if (fetchError.name === "AbortError" || fetchError.message?.includes("timeout")) {
        return { port, status: "filtered" };
      }
      
      // Other errors might still indicate an open port (TLS errors, etc.)
      if (fetchError.message?.includes("certificate") || 
          fetchError.message?.includes("SSL") ||
          fetchError.message?.includes("TLS")) {
        return {
          port,
          status: "open",
          service: commonPorts[port] || "unknown",
          responseTime: Date.now() - startTime,
        };
      }
      
      return { port, status: "closed" };
    }
  } catch (error) {
    return { port, status: "closed" };
  }
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      throw new Error("No authorization header");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { host, startPort, endPort, scanId }: ScanRequest = await req.json();

    console.log(`Starting port scan on ${host} from ${startPort} to ${endPort}`);

    // Validate inputs
    if (!host || !startPort || !endPort) {
      throw new Error("Missing required parameters");
    }

    if (startPort < 1 || endPort > 65535 || startPort > endPort) {
      throw new Error("Invalid port range");
    }

    if (endPort - startPort > 100) {
      throw new Error("Maximum 100 ports per scan for rate limiting");
    }

    // Get user from token
    const token = authHeader.replace("Bearer ", "");
    const { data: userData } = await supabase.auth.getUser(token);
    
    if (!userData.user) {
      throw new Error("Invalid user");
    }

    // Create scan record if not provided
    let currentScanId = scanId;
    if (!currentScanId) {
      const { data: scanData, error: scanError } = await supabase
        .from("port_scans")
        .insert({
          user_id: userData.user.id,
          target_host: host,
          start_port: startPort,
          end_port: endPort,
          status: "running",
        })
        .select()
        .single();

      if (scanError) throw scanError;
      currentScanId = scanData.id;
    }

    // Scan ports
    const results: PortResult[] = [];
    const batchSize = 10;

    for (let i = startPort; i <= endPort; i += batchSize) {
      const batch = [];
      for (let j = i; j < Math.min(i + batchSize, endPort + 1); j++) {
        batch.push(scanPort(host, j));
      }
      
      const batchResults = await Promise.all(batch);
      results.push(...batchResults);
      
      // Update progress
      await supabase
        .from("port_scans")
        .update({ results: results })
        .eq("id", currentScanId);
    }

    // Mark scan as completed
    await supabase
      .from("port_scans")
      .update({ 
        status: "completed", 
        results: results,
        completed_at: new Date().toISOString()
      })
      .eq("id", currentScanId);

    // Log audit event
    await supabase.from("security_audit_logs").insert({
      user_id: userData.user.id,
      action: "port_scan_completed",
      details: { 
        host, 
        startPort, 
        endPort, 
        openPorts: results.filter(r => r.status === "open").length 
      },
    });

    console.log(`Scan completed: ${results.filter(r => r.status === "open").length} open ports found`);

    return new Response(JSON.stringify({ 
      success: true, 
      scanId: currentScanId,
      results 
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error: any) {
    console.error("Port scan error:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
