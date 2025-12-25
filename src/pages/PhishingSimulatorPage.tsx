import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { 
  Mail, 
  Send, 
  Plus, 
  Trash2, 
  Eye, 
  MousePointer, 
  Clock, 
  CheckCircle2, 
  XCircle,
  AlertTriangle,
  Users,
  BarChart3,
  FileText,
  Zap,
  Shield
} from "lucide-react";

interface Campaign {
  id: string;
  name: string;
  subject: string;
  body_html: string;
  sender_name: string;
  sender_email: string;
  status: string;
  created_at: string;
}

interface Target {
  id: string;
  campaign_id: string;
  email: string;
  name: string;
  status: string;
  sent_at: string | null;
  opened_at: string | null;
  clicked_at: string | null;
}

const emailTemplates = [
  { id: "password_reset", name: "Password Reset", icon: "🔑" },
  { id: "invoice", name: "Invoice/Payment", icon: "💰" },
  { id: "urgent_action", name: "Urgent Action", icon: "⚠️" },
  { id: "it_support", name: "IT Support", icon: "🖥️" },
  { id: "ceo_fraud", name: "CEO Fraud", icon: "👔" },
  { id: "custom", name: "Custom Template", icon: "✏️" },
];

export default function PhishingSimulatorPage() {
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [isCreating, setIsCreating] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [sendProgress, setSendProgress] = useState(0);

  // New campaign form
  const [newCampaign, setNewCampaign] = useState({
    name: "",
    subject: "",
    body_html: "",
    sender_name: "Security Team",
    sender_email: "security@yourdomain.com",
  });

  // New targets
  const [newTargetEmail, setNewTargetEmail] = useState("");
  const [newTargetName, setNewTargetName] = useState("");
  const [selectedTemplate, setSelectedTemplate] = useState("");

  useEffect(() => {
    if (!authLoading && !user) {
      navigate("/auth");
    }
  }, [user, authLoading, navigate]);

  useEffect(() => {
    if (user) {
      fetchCampaigns();
    }
  }, [user]);

  useEffect(() => {
    if (selectedCampaign) {
      fetchTargets(selectedCampaign.id);
      
      // Set up realtime subscription for target updates
      const channel = supabase
        .channel('campaign-targets')
        .on(
          'postgres_changes',
          {
            event: '*',
            schema: 'public',
            table: 'campaign_targets',
            filter: `campaign_id=eq.${selectedCampaign.id}`
          },
          () => {
            fetchTargets(selectedCampaign.id);
          }
        )
        .subscribe();

      return () => {
        supabase.removeChannel(channel);
      };
    }
  }, [selectedCampaign]);

  const fetchCampaigns = async () => {
    const { data, error } = await supabase
      .from("phishing_campaigns")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      toast({ title: "Error fetching campaigns", description: error.message, variant: "destructive" });
    } else {
      setCampaigns(data || []);
    }
  };

  const fetchTargets = async (campaignId: string) => {
    const { data, error } = await supabase
      .from("campaign_targets")
      .select("*")
      .eq("campaign_id", campaignId)
      .order("created_at", { ascending: false });

    if (error) {
      toast({ title: "Error fetching targets", description: error.message, variant: "destructive" });
    } else {
      setTargets(data || []);
    }
  };

  const loadTemplate = async (templateId: string) => {
    setSelectedTemplate(templateId);
    
    try {
      const { data, error } = await supabase.functions.invoke("generate-phishing-template", {
        body: { type: templateId }
      });

      if (error) throw error;

      setNewCampaign(prev => ({
        ...prev,
        subject: data.subject,
        body_html: data.body,
      }));

      toast({ title: "Template loaded", description: `${templateId} template applied` });
    } catch (error: any) {
      toast({ title: "Error loading template", description: error.message, variant: "destructive" });
    }
  };

  const createCampaign = async () => {
    if (!newCampaign.name || !newCampaign.subject || !newCampaign.body_html) {
      toast({ title: "Missing fields", description: "Please fill all required fields", variant: "destructive" });
      return;
    }

    setIsCreating(true);

    const { data, error } = await supabase
      .from("phishing_campaigns")
      .insert({
        ...newCampaign,
        user_id: user?.id,
      })
      .select()
      .single();

    setIsCreating(false);

    if (error) {
      toast({ title: "Error creating campaign", description: error.message, variant: "destructive" });
    } else {
      toast({ title: "Campaign created", description: "Your campaign is ready" });
      setCampaigns([data, ...campaigns]);
      setSelectedCampaign(data);
      setNewCampaign({
        name: "",
        subject: "",
        body_html: "",
        sender_name: "Security Team",
        sender_email: "security@yourdomain.com",
      });
    }
  };

  const addTarget = async () => {
    if (!selectedCampaign || !newTargetEmail) return;

    const { data, error } = await supabase
      .from("campaign_targets")
      .insert({
        campaign_id: selectedCampaign.id,
        email: newTargetEmail,
        name: newTargetName || null,
      })
      .select()
      .single();

    if (error) {
      toast({ title: "Error adding target", description: error.message, variant: "destructive" });
    } else {
      setTargets([data, ...targets]);
      setNewTargetEmail("");
      setNewTargetName("");
      toast({ title: "Target added" });
    }
  };

  const removeTarget = async (targetId: string) => {
    const { error } = await supabase
      .from("campaign_targets")
      .delete()
      .eq("id", targetId);

    if (error) {
      toast({ title: "Error removing target", description: error.message, variant: "destructive" });
    } else {
      setTargets(targets.filter(t => t.id !== targetId));
    }
  };

  const launchCampaign = async () => {
    if (!selectedCampaign || targets.length === 0) {
      toast({ title: "No targets", description: "Add targets before launching", variant: "destructive" });
      return;
    }

    setIsSending(true);
    setSendProgress(0);

    const pendingTargets = targets.filter(t => t.status === "pending");
    let sent = 0;

    for (const target of pendingTargets) {
      try {
        const { error } = await supabase.functions.invoke("send-phishing-email", {
          body: {
            campaignId: selectedCampaign.id,
            targetId: target.id,
            targetEmail: target.email,
            targetName: target.name,
            subject: selectedCampaign.subject,
            bodyHtml: selectedCampaign.body_html,
            senderName: selectedCampaign.sender_name,
            senderEmail: selectedCampaign.sender_email,
            trackingUrl: window.location.origin + "/learning",
          }
        });

        if (error) throw error;
        sent++;
      } catch (error: any) {
        console.error(`Failed to send to ${target.email}:`, error);
      }

      setSendProgress(Math.round((sent / pendingTargets.length) * 100));
    }

    // Update campaign status
    await supabase
      .from("phishing_campaigns")
      .update({ status: "active" })
      .eq("id", selectedCampaign.id);

    setIsSending(false);
    toast({ 
      title: "Campaign launched!", 
      description: `Sent ${sent} of ${pendingTargets.length} emails` 
    });

    fetchTargets(selectedCampaign.id);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pending": return <Clock className="w-4 h-4 text-muted-foreground" />;
      case "sent": return <Send className="w-4 h-4 text-blue-500" />;
      case "delivered": return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      case "opened": return <Eye className="w-4 h-4 text-yellow-500" />;
      case "clicked": return <MousePointer className="w-4 h-4 text-red-500" />;
      case "failed": return <XCircle className="w-4 h-4 text-destructive" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
      pending: "outline",
      sent: "secondary",
      delivered: "default",
      opened: "default",
      clicked: "destructive",
      failed: "destructive",
    };
    return <Badge variant={variants[status] || "outline"}>{status.toUpperCase()}</Badge>;
  };

  // Statistics
  const stats = {
    total: targets.length,
    sent: targets.filter(t => ["sent", "delivered", "opened", "clicked"].includes(t.status)).length,
    opened: targets.filter(t => ["opened", "clicked"].includes(t.status)).length,
    clicked: targets.filter(t => t.status === "clicked").length,
  };

  const openRate = stats.sent > 0 ? Math.round((stats.opened / stats.sent) * 100) : 0;
  const clickRate = stats.sent > 0 ? Math.round((stats.clicked / stats.sent) * 100) : 0;

  if (authLoading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Mail className="w-8 h-8 text-primary" />
              Phishing Simulation Platform
            </h1>
            <p className="text-muted-foreground mt-1">
              Security awareness training through controlled email simulations
            </p>
          </div>
          <Badge variant="outline" className="text-lg px-4 py-2">
            <Shield className="w-4 h-4 mr-2" />
            Security Officer Mode
          </Badge>
        </div>

        {/* Warning Banner */}
        <Card className="border-warning bg-warning/10">
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-6 h-6 text-warning" />
              <div>
                <p className="font-medium">⚠️ Authorized Use Only</p>
                <p className="text-sm text-muted-foreground">
                  This platform is for security awareness training only. All emails are clearly marked as simulations.
                  Never use for deceptive purposes. Ensure you have proper authorization.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Tabs defaultValue="campaigns" className="space-y-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="campaigns" className="flex items-center gap-2">
              <FileText className="w-4 h-4" />
              Campaigns
            </TabsTrigger>
            <TabsTrigger value="targets" className="flex items-center gap-2">
              <Users className="w-4 h-4" />
              Targets
            </TabsTrigger>
            <TabsTrigger value="analytics" className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Analytics
            </TabsTrigger>
          </TabsList>

          {/* Campaigns Tab */}
          <TabsContent value="campaigns" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Create Campaign */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Plus className="w-5 h-5" />
                    Create Campaign
                  </CardTitle>
                  <CardDescription>Design your phishing simulation email</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="text-sm font-medium">Campaign Name</label>
                    <Input
                      placeholder="Q4 Security Awareness Test"
                      value={newCampaign.name}
                      onChange={(e) => setNewCampaign({ ...newCampaign, name: e.target.value })}
                    />
                  </div>

                  <div>
                    <label className="text-sm font-medium">Email Template</label>
                    <div className="grid grid-cols-3 gap-2 mt-2">
                      {emailTemplates.map((template) => (
                        <Button
                          key={template.id}
                          variant={selectedTemplate === template.id ? "default" : "outline"}
                          size="sm"
                          onClick={() => loadTemplate(template.id)}
                          className="flex flex-col h-auto py-3"
                        >
                          <span className="text-lg">{template.icon}</span>
                          <span className="text-xs mt-1">{template.name}</span>
                        </Button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="text-sm font-medium">Subject Line</label>
                    <Input
                      placeholder="Subject..."
                      value={newCampaign.subject}
                      onChange={(e) => setNewCampaign({ ...newCampaign, subject: e.target.value })}
                    />
                  </div>

                  <div>
                    <label className="text-sm font-medium">Email Body (HTML)</label>
                    <Textarea
                      placeholder="<p>Email content...</p>"
                      value={newCampaign.body_html}
                      onChange={(e) => setNewCampaign({ ...newCampaign, body_html: e.target.value })}
                      rows={6}
                      className="font-mono text-sm"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Use [TARGET_NAME] for personalization and [CLICK_LINK] for tracking link
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium">Sender Name</label>
                      <Input
                        value={newCampaign.sender_name}
                        onChange={(e) => setNewCampaign({ ...newCampaign, sender_name: e.target.value })}
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium">Sender Email</label>
                      <Input
                        value={newCampaign.sender_email}
                        onChange={(e) => setNewCampaign({ ...newCampaign, sender_email: e.target.value })}
                      />
                    </div>
                  </div>

                  <Button 
                    onClick={createCampaign} 
                    disabled={isCreating}
                    className="w-full"
                  >
                    {isCreating ? "Creating..." : "Create Campaign"}
                  </Button>
                </CardContent>
              </Card>

              {/* Campaign List */}
              <Card>
                <CardHeader>
                  <CardTitle>Your Campaigns</CardTitle>
                  <CardDescription>Select a campaign to manage</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-[500px] overflow-auto">
                    {campaigns.length === 0 ? (
                      <p className="text-muted-foreground text-center py-8">
                        No campaigns yet. Create your first one!
                      </p>
                    ) : (
                      campaigns.map((campaign) => (
                        <div
                          key={campaign.id}
                          onClick={() => setSelectedCampaign(campaign)}
                          className={`p-4 rounded-lg border cursor-pointer transition-all ${
                            selectedCampaign?.id === campaign.id 
                              ? "border-primary bg-primary/5" 
                              : "hover:border-primary/50"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="font-medium">{campaign.name}</p>
                              <p className="text-sm text-muted-foreground truncate">
                                {campaign.subject}
                              </p>
                            </div>
                            {getStatusBadge(campaign.status)}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Targets Tab */}
          <TabsContent value="targets" className="space-y-6">
            {!selectedCampaign ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <Users className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">Select a campaign first to manage targets</p>
                </CardContent>
              </Card>
            ) : (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle>Campaign: {selectedCampaign.name}</CardTitle>
                    <CardDescription>Add email targets for this campaign</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex gap-4">
                      <Input
                        placeholder="target@example.com"
                        value={newTargetEmail}
                        onChange={(e) => setNewTargetEmail(e.target.value)}
                        className="flex-1"
                      />
                      <Input
                        placeholder="Name (optional)"
                        value={newTargetName}
                        onChange={(e) => setNewTargetName(e.target.value)}
                        className="w-48"
                      />
                      <Button onClick={addTarget}>
                        <Plus className="w-4 h-4 mr-2" />
                        Add
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                      <CardTitle>Target List ({targets.length})</CardTitle>
                      <CardDescription>Real-time status tracking</CardDescription>
                    </div>
                    <Button 
                      onClick={launchCampaign} 
                      disabled={isSending || targets.length === 0}
                      variant="cyber"
                    >
                      {isSending ? (
                        <>Sending... {sendProgress}%</>
                      ) : (
                        <>
                          <Zap className="w-4 h-4 mr-2" />
                          Launch Campaign
                        </>
                      )}
                    </Button>
                  </CardHeader>
                  <CardContent>
                    {isSending && (
                      <Progress value={sendProgress} className="mb-4" />
                    )}
                    
                    <div className="space-y-2 max-h-[400px] overflow-auto">
                      {targets.length === 0 ? (
                        <p className="text-muted-foreground text-center py-8">
                          No targets added yet
                        </p>
                      ) : (
                        targets.map((target) => (
                          <div
                            key={target.id}
                            className="flex items-center justify-between p-3 rounded-lg border bg-card"
                          >
                            <div className="flex items-center gap-3">
                              {getStatusIcon(target.status)}
                              <div>
                                <p className="font-medium">{target.email}</p>
                                {target.name && (
                                  <p className="text-sm text-muted-foreground">{target.name}</p>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center gap-3">
                              {target.sent_at && (
                                <span className="text-xs text-muted-foreground">
                                  Sent: {new Date(target.sent_at).toLocaleString()}
                                </span>
                              )}
                              {target.clicked_at && (
                                <span className="text-xs text-red-500 font-medium">
                                  Clicked!
                                </span>
                              )}
                              {getStatusBadge(target.status)}
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => removeTarget(target.id)}
                                disabled={target.status !== "pending"}
                              >
                                <Trash2 className="w-4 h-4 text-destructive" />
                              </Button>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="pt-6">
                  <div className="text-center">
                    <Users className="w-8 h-8 mx-auto text-primary mb-2" />
                    <p className="text-3xl font-bold">{stats.total}</p>
                    <p className="text-sm text-muted-foreground">Total Targets</p>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="text-center">
                    <Send className="w-8 h-8 mx-auto text-blue-500 mb-2" />
                    <p className="text-3xl font-bold">{stats.sent}</p>
                    <p className="text-sm text-muted-foreground">Emails Sent</p>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="text-center">
                    <Eye className="w-8 h-8 mx-auto text-yellow-500 mb-2" />
                    <p className="text-3xl font-bold">{openRate}%</p>
                    <p className="text-sm text-muted-foreground">Open Rate</p>
                  </div>
                </CardContent>
              </Card>
              <Card className="border-destructive">
                <CardContent className="pt-6">
                  <div className="text-center">
                    <MousePointer className="w-8 h-8 mx-auto text-red-500 mb-2" />
                    <p className="text-3xl font-bold text-red-500">{clickRate}%</p>
                    <p className="text-sm text-muted-foreground">Click Rate (Vulnerable)</p>
                  </div>
                </CardContent>
              </Card>
            </div>

            {stats.clicked > 0 && (
              <Card className="border-destructive bg-destructive/5">
                <CardHeader>
                  <CardTitle className="text-destructive flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5" />
                    Vulnerable Users Identified
                  </CardTitle>
                  <CardDescription>
                    These users clicked on the simulated phishing link and need additional training
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {targets
                      .filter(t => t.status === "clicked")
                      .map((target) => (
                        <div key={target.id} className="flex items-center justify-between p-3 rounded-lg bg-background border">
                          <div>
                            <p className="font-medium">{target.email}</p>
                            <p className="text-sm text-muted-foreground">{target.name || "Unknown"}</p>
                          </div>
                          <div className="text-right">
                            <p className="text-sm text-destructive font-medium">
                              Clicked at: {new Date(target.clicked_at!).toLocaleString()}
                            </p>
                            <Button variant="outline" size="sm" className="mt-1">
                              Assign Training
                            </Button>
                          </div>
                        </div>
                      ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
}
