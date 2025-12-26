import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { Resend } from "https://esm.sh/resend@2.0.0";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const resendApiKey = Deno.env.get("RESEND_API_KEY");
    if (!resendApiKey) {
      console.error("RESEND_API_KEY is not configured");
      throw new Error("Email service not configured. Please add RESEND_API_KEY.");
    }

    const resend = new Resend(resendApiKey);

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      console.error("No authorization header provided");
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

    console.log(`📧 Sending phishing simulation email to ${targetEmail}`);
    console.log(`Campaign: ${campaignId}, Target: ${targetId}`);

    // Create tracking pixel URL
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const projectUrl = supabaseUrl?.replace('.supabase.co', '.functions.supabase.co');
    const trackingPixelUrl = `${projectUrl}/functions/v1/track-email?tid=${targetId}&action=open`;
    const clickUrl = `${projectUrl}/functions/v1/track-email?tid=${targetId}&action=click&redirect=${encodeURIComponent(trackingUrl)}`;

    console.log(`Tracking URLs configured: pixel=${trackingPixelUrl}`);

    // Build email with tracking - clean professional format
    const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5;">
    <tr>
      <td align="center" style="padding: 40px 20px;">
        <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
          <!-- Security Training Banner -->
          <tr>
            <td style="background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%); color: white; padding: 12px 20px; text-align: center; font-size: 13px; font-weight: 500; border-radius: 8px 8px 0 0;">
              ⚠️ SECURITY AWARENESS SIMULATION - This is an authorized training exercise
            </td>
          </tr>
          
          <!-- Main Content -->
          <tr>
            <td style="padding: 40px 40px 30px;">
              ${bodyHtml.replace(/\[CLICK_LINK\]/g, clickUrl).replace(/\[TARGET_NAME\]/g, targetName || 'User')}
            </td>
          </tr>
          
          <!-- Security Notice Footer -->
          <tr>
            <td style="padding: 0 40px 40px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f8f9fa; border-left: 4px solid #ff6b35; border-radius: 0 4px 4px 0;">
                <tr>
                  <td style="padding: 20px;">
                    <p style="margin: 0 0 8px 0; font-weight: 600; color: #333; font-size: 14px;">🔒 Security Training Notice</p>
                    <p style="margin: 0; color: #666; font-size: 13px; line-height: 1.5;">
                      This email is part of a controlled security awareness training conducted by your organization's security team. 
                      No credentials are collected and no personal data is harvested.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  <img src="${trackingPixelUrl}" width="1" height="1" style="display:none;" alt="" />
</body>
</html>
    `;

    console.log(`Sending email via Resend to: ${targetEmail}`);

    // Send via Resend using their test domain
    const emailResponse = await resend.emails.send({
      from: `${senderName} <onboarding@resend.dev>`,
      to: [targetEmail],
      subject: `[SECURITY TRAINING] ${subject}`,
      html: emailHtml,
      reply_to: senderEmail,
    });

    console.log("✅ Email sent successfully:", JSON.stringify(emailResponse));

    // Update target status to sent
    const { error: updateError } = await supabase
      .from("campaign_targets")
      .update({ status: "sent", sent_at: new Date().toISOString() })
      .eq("id", targetId);

    if (updateError) {
      console.error("Failed to update target status:", updateError);
    }

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
    console.error("❌ Error sending email:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
