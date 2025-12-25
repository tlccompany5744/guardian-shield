-- Create phishing campaigns table
CREATE TABLE public.phishing_campaigns (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  body_html TEXT NOT NULL,
  sender_name TEXT NOT NULL DEFAULT 'Security Team',
  sender_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'completed', 'paused')),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create campaign targets table
CREATE TABLE public.campaign_targets (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  campaign_id UUID NOT NULL REFERENCES public.phishing_campaigns(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  name TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'delivered', 'opened', 'clicked', 'failed')),
  sent_at TIMESTAMP WITH TIME ZONE,
  opened_at TIMESTAMP WITH TIME ZONE,
  clicked_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create port scan results table
CREATE TABLE public.port_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  target_host TEXT NOT NULL,
  start_port INTEGER NOT NULL,
  end_port INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
  results JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE
);

-- Create audit logs table
CREATE TABLE public.security_audit_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  action TEXT NOT NULL,
  details JSONB,
  ip_address TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.phishing_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.campaign_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.port_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_audit_logs ENABLE ROW LEVEL SECURITY;

-- Policies for phishing_campaigns
CREATE POLICY "Users can view their own campaigns" 
ON public.phishing_campaigns FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create campaigns" 
ON public.phishing_campaigns FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own campaigns" 
ON public.phishing_campaigns FOR UPDATE 
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own campaigns" 
ON public.phishing_campaigns FOR DELETE 
USING (auth.uid() = user_id);

-- Policies for campaign_targets
CREATE POLICY "Users can view targets of their campaigns" 
ON public.campaign_targets FOR SELECT 
USING (EXISTS (SELECT 1 FROM public.phishing_campaigns WHERE id = campaign_id AND user_id = auth.uid()));

CREATE POLICY "Users can add targets to their campaigns" 
ON public.campaign_targets FOR INSERT 
WITH CHECK (EXISTS (SELECT 1 FROM public.phishing_campaigns WHERE id = campaign_id AND user_id = auth.uid()));

CREATE POLICY "Users can update targets of their campaigns" 
ON public.campaign_targets FOR UPDATE 
USING (EXISTS (SELECT 1 FROM public.phishing_campaigns WHERE id = campaign_id AND user_id = auth.uid()));

CREATE POLICY "Users can delete targets from their campaigns" 
ON public.campaign_targets FOR DELETE 
USING (EXISTS (SELECT 1 FROM public.phishing_campaigns WHERE id = campaign_id AND user_id = auth.uid()));

-- Policies for port_scans
CREATE POLICY "Users can view their own scans" 
ON public.port_scans FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create scans" 
ON public.port_scans FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans" 
ON public.port_scans FOR UPDATE 
USING (auth.uid() = user_id);

-- Policies for audit_logs
CREATE POLICY "Users can view their own audit logs" 
ON public.security_audit_logs FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create audit logs" 
ON public.security_audit_logs FOR INSERT 
WITH CHECK (auth.uid() = user_id);

-- Create indexes for performance
CREATE INDEX idx_campaign_targets_campaign_id ON public.campaign_targets(campaign_id);
CREATE INDEX idx_campaign_targets_status ON public.campaign_targets(status);
CREATE INDEX idx_port_scans_user_id ON public.port_scans(user_id);
CREATE INDEX idx_audit_logs_user_id ON public.security_audit_logs(user_id);

-- Enable realtime for tracking
ALTER PUBLICATION supabase_realtime ADD TABLE public.campaign_targets;
ALTER PUBLICATION supabase_realtime ADD TABLE public.port_scans;