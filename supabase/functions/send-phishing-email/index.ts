import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { Resend } from "https://esm.sh/resend@2.0.0";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const resend = new Resend(Deno.env.get("RESEND_API_KEY"));

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface SendEmailRequest {
  campaignId: string;
  targetId: string;
  targetEmail: string;
  targetName: string;
  subject: string;
  bodyHtml: string;
  senderName: string;
  senderEmail: string;
  trackingUrl: string;
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

    const {
      campaignId,
      targetId,
      targetEmail,
      targetName,
      subject,
      bodyHtml,
      senderName,
      senderEmail,
      trackingUrl,
    }: SendEmailRequest = await req.json();

    console.log(`Sending phishing simulation email to ${targetEmail}`);

    // Create tracking pixel URL
    const projectUrl = Deno.env.get("SUPABASE_URL")?.replace('.supabase.co', '.functions.supabase.co');
    const trackingPixelUrl = `${projectUrl}/functions/v1/track-email?tid=${targetId}&action=open`;
    const clickUrl = `${projectUrl}/functions/v1/track-email?tid=${targetId}&action=click&redirect=${encodeURIComponent(trackingUrl)}`;

    // Build email with tracking
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #ff6b35; color: white; padding: 10px; text-align: center; font-size: 12px;">
          ⚠️ SECURITY AWARENESS SIMULATION - This is a training exercise
        </div>
        
        ${bodyHtml.replace(/\[CLICK_LINK\]/g, clickUrl).replace(/\[TARGET_NAME\]/g, targetName || 'User')}
        
        <div style="margin-top: 30px; padding: 15px; background: #f0f0f0; border-left: 4px solid #ff6b35;">
          <strong>🔒 Security Notice:</strong><br/>
          This email is part of a controlled security awareness training conducted by your organization.
          No credentials are collected. No data is harvested.
        </div>
        
        <img src="${trackingPixelUrl}" width="1" height="1" style="display:none;" alt="" />
      </div>
    `;

    const emailResponse = await resend.emails.send({
      from: `${senderName} <${senderEmail}>`,
      to: [targetEmail],
      subject: `[SECURITY TRAINING] ${subject}`,
      html: emailHtml,
    });

    console.log("Email sent successfully:", emailResponse);

    // Update target status to sent
    await supabase
      .from("campaign_targets")
      .update({ status: "sent", sent_at: new Date().toISOString() })
      .eq("id", targetId);

    // Log audit event
    const token = authHeader.replace("Bearer ", "");
    const { data: userData } = await supabase.auth.getUser(token);
    
    await supabase.from("security_audit_logs").insert({
      user_id: userData.user?.id,
      action: "email_sent",
      details: { campaignId, targetId, targetEmail },
    });

    return new Response(JSON.stringify({ success: true, emailResponse }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error: any) {
    console.error("Error sending email:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
