import { serve } from "https://deno.land/std@0.190.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface TemplateRequest {
  type: "password_reset" | "invoice" | "urgent_action" | "it_support" | "ceo_fraud" | "custom";
  companyName?: string;
  targetName?: string;
}

const templates: Record<string, { subject: string; body: string }> = {
  password_reset: {
    subject: "Urgent: Your Password Expires in 24 Hours",
    body: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <img src="https://via.placeholder.com/150x50?text=Company+Logo" alt="Logo" style="margin-bottom: 20px;"/>
        <h2>Password Expiration Notice</h2>
        <p>Dear [TARGET_NAME],</p>
        <p>Your password will expire in <strong>24 hours</strong>. To avoid losing access to your account, please reset your password immediately.</p>
        <p style="margin: 30px 0;">
          <a href="[CLICK_LINK]" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
            Reset Password Now
          </a>
        </p>
        <p style="color: #666;">If you did not request this, please contact IT support immediately.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;"/>
        <p style="color: #888; font-size: 12px;">This is an automated message from IT Security.</p>
      </div>
    `,
  },
  invoice: {
    subject: "Invoice #INV-2024-8847 Attached - Payment Required",
    body: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Invoice Notification</h2>
        <p>Dear [TARGET_NAME],</p>
        <p>Please find attached invoice <strong>#INV-2024-8847</strong> for services rendered.</p>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr style="background: #f5f5f5;">
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Invoice Number</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">INV-2024-8847</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Amount Due</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">$4,299.00</td>
          </tr>
          <tr style="background: #f5f5f5;">
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Due Date</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Within 48 hours</td>
          </tr>
        </table>
        <p>
          <a href="[CLICK_LINK]" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
            View Invoice
          </a>
        </p>
      </div>
    `,
  },
  urgent_action: {
    subject: "⚠️ Immediate Action Required - Account Suspended",
    body: `
      <div style="font-family: Arial, sans-serif; padding: 20px; background: #fff3cd; border-left: 4px solid #ffc107;">
        <h2 style="color: #856404;">⚠️ Account Suspension Notice</h2>
        <p>Dear [TARGET_NAME],</p>
        <p>We have detected <strong>unusual activity</strong> on your account and have temporarily suspended access.</p>
        <p>To restore access, please verify your identity within the next <strong>2 hours</strong>.</p>
        <p style="margin: 30px 0;">
          <a href="[CLICK_LINK]" style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 16px;">
            Verify Now
          </a>
        </p>
        <p style="color: #666;">Failure to verify may result in permanent account closure.</p>
      </div>
    `,
  },
  it_support: {
    subject: "IT Support: Required Software Update",
    body: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="background: #0078d4; color: white; padding: 15px; margin-bottom: 20px;">
          <strong>IT Support Notification</strong>
        </div>
        <p>Hello [TARGET_NAME],</p>
        <p>As part of our security compliance, all employees must install the latest security update by end of day.</p>
        <p>This update patches critical vulnerabilities in our systems.</p>
        <p style="margin: 30px 0;">
          <a href="[CLICK_LINK]" style="background: #0078d4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
            Download Update
          </a>
        </p>
        <p style="color: #666; font-size: 12px;">
          IT Help Desk<br/>
          Extension: 4357
        </p>
      </div>
    `,
  },
  ceo_fraud: {
    subject: "Quick Request - Confidential",
    body: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <p>[TARGET_NAME],</p>
        <p>Are you at your desk? I need a quick favor.</p>
        <p>I'm in a meeting and need you to handle something urgently. Can you click below and complete a quick task for me?</p>
        <p style="margin: 30px 0;">
          <a href="[CLICK_LINK]" style="background: #333; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
            View Request
          </a>
        </p>
        <p>Thanks,<br/>CEO</p>
        <p style="color: #888; font-size: 12px;"><em>Sent from my iPhone</em></p>
      </div>
    `,
  },
  custom: {
    subject: "Custom Training Email",
    body: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <p>Dear [TARGET_NAME],</p>
        <p>This is a custom phishing simulation template. Edit this content to create your own scenario.</p>
        <p style="margin: 30px 0;">
          <a href="[CLICK_LINK]" style="background: #6c757d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
            Click Here
          </a>
        </p>
      </div>
    `,
  },
};

serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { type, companyName, targetName }: TemplateRequest = await req.json();

    const template = templates[type] || templates.custom;

    let body = template.body;
    if (companyName) {
      body = body.replace(/Company/g, companyName);
    }

    return new Response(JSON.stringify({
      subject: template.subject,
      body: body,
      type: type,
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error: any) {
    console.error("Template generation error:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
