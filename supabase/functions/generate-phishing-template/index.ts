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
    subject: "Action Required: Your Password Will Expire in 24 Hours",
    body: `
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="padding-bottom: 25px; border-bottom: 3px solid #0066cc;">
            <table role="presentation" cellspacing="0" cellpadding="0">
              <tr>
                <td style="background: linear-gradient(135deg, #0066cc 0%, #004499 100%); padding: 12px 20px; border-radius: 6px;">
                  <span style="color: white; font-size: 18px; font-weight: 700; letter-spacing: 0.5px;">SECURE ACCESS</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding: 30px 0;">
            <h2 style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 22px; font-weight: 600;">Password Expiration Notice</h2>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">Dear [TARGET_NAME],</p>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">
              Our security systems have detected that your password will expire in <strong>24 hours</strong>. 
              To maintain uninterrupted access to your corporate account and resources, please reset your password immediately.
            </p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 0 4px 4px 0;">
              <tr>
                <td style="padding: 15px 20px;">
                  <p style="margin: 0; color: #856404; font-size: 14px;">
                    <strong>⏰ Time Remaining:</strong> Your password will expire on ${new Date(Date.now() + 86400000).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} at 11:59 PM
                  </p>
                </td>
              </tr>
            </table>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 30px 0;">
              <tr>
                <td style="background: linear-gradient(135deg, #0066cc 0%, #004499 100%); border-radius: 6px;">
                  <a href="[CLICK_LINK]" style="display: inline-block; padding: 14px 32px; color: white; text-decoration: none; font-size: 15px; font-weight: 600;">
                    Reset Password Now →
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin: 0; color: #666; font-size: 13px; line-height: 1.5;">
              If you did not request this change or believe this message was sent in error, please contact IT Support immediately at extension 4357.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding-top: 25px; border-top: 1px solid #e0e0e0;">
            <p style="margin: 0; color: #888; font-size: 12px; line-height: 1.5;">
              This is an automated security notification from the IT Security Department.<br/>
              © ${new Date().getFullYear()} Corporate IT Security. All rights reserved.
            </p>
          </td>
        </tr>
      </table>
    `,
  },
  invoice: {
    subject: "Invoice #INV-${Math.floor(Math.random() * 90000) + 10000} - Payment Due Within 48 Hours",
    body: `
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="padding-bottom: 25px; border-bottom: 3px solid #28a745;">
            <table role="presentation" cellspacing="0" cellpadding="0">
              <tr>
                <td>
                  <span style="font-size: 24px; font-weight: 700; color: #1a1a1a;">VENDOR SERVICES INC.</span>
                  <p style="margin: 5px 0 0 0; color: #666; font-size: 13px;">Accounts Receivable Department</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding: 30px 0;">
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">Dear [TARGET_NAME],</p>
            <p style="margin: 0 0 20px 0; color: #333; font-size: 15px; line-height: 1.6;">
              Please find below the details for Invoice <strong>#INV-2024-${Math.floor(Math.random() * 9000) + 1000}</strong> for professional services rendered during the current billing period.
            </p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden;">
              <tr style="background-color: #f8f9fa;">
                <td style="padding: 12px 16px; font-weight: 600; color: #333; font-size: 14px; border-bottom: 1px solid #e0e0e0;">Invoice Details</td>
                <td style="padding: 12px 16px; border-bottom: 1px solid #e0e0e0;"></td>
              </tr>
              <tr>
                <td style="padding: 12px 16px; color: #666; font-size: 14px; border-bottom: 1px solid #f0f0f0;">Invoice Number</td>
                <td style="padding: 12px 16px; color: #333; font-size: 14px; font-weight: 500; border-bottom: 1px solid #f0f0f0;">INV-2024-${Math.floor(Math.random() * 9000) + 1000}</td>
              </tr>
              <tr>
                <td style="padding: 12px 16px; color: #666; font-size: 14px; border-bottom: 1px solid #f0f0f0;">Issue Date</td>
                <td style="padding: 12px 16px; color: #333; font-size: 14px; border-bottom: 1px solid #f0f0f0;">${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</td>
              </tr>
              <tr>
                <td style="padding: 12px 16px; color: #666; font-size: 14px; border-bottom: 1px solid #f0f0f0;">Due Date</td>
                <td style="padding: 12px 16px; color: #dc3545; font-size: 14px; font-weight: 600; border-bottom: 1px solid #f0f0f0;">${new Date(Date.now() + 172800000).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</td>
              </tr>
              <tr style="background-color: #f8f9fa;">
                <td style="padding: 14px 16px; color: #333; font-size: 15px; font-weight: 600;">Amount Due</td>
                <td style="padding: 14px 16px; color: #28a745; font-size: 18px; font-weight: 700;">$${(Math.floor(Math.random() * 5000) + 1500).toLocaleString()}.00</td>
              </tr>
            </table>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 30px 0;">
              <tr>
                <td style="background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); border-radius: 6px;">
                  <a href="[CLICK_LINK]" style="display: inline-block; padding: 14px 32px; color: white; text-decoration: none; font-size: 15px; font-weight: 600;">
                    View & Pay Invoice →
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin: 0; color: #666; font-size: 13px; line-height: 1.5;">
              Please ensure payment is submitted before the due date to avoid late fees. If you have any questions regarding this invoice, please contact our billing department.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding-top: 25px; border-top: 1px solid #e0e0e0;">
            <p style="margin: 0; color: #888; font-size: 12px; line-height: 1.5;">
              Vendor Services Inc. | Accounts Receivable<br/>
              1234 Business Center Drive, Suite 500 | New York, NY 10001<br/>
              billing@vendorservices.com | (555) 123-4567
            </p>
          </td>
        </tr>
      </table>
    `,
  },
  urgent_action: {
    subject: "🔴 URGENT: Immediate Action Required - Account Security Alert",
    body: `
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%); padding: 20px; border-radius: 6px 6px 0 0;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
              <tr>
                <td>
                  <span style="color: white; font-size: 20px; font-weight: 700;">⚠️ SECURITY ALERT</span>
                  <p style="margin: 5px 0 0 0; color: rgba(255,255,255,0.9); font-size: 13px;">Immediate attention required</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="background-color: #fff5f5; padding: 30px; border: 1px solid #f5c6cb; border-top: none; border-radius: 0 0 6px 6px;">
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">Dear [TARGET_NAME],</p>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">
              Our automated security monitoring systems have detected <strong>suspicious activity</strong> originating from your account. As a precautionary measure, we have temporarily restricted access to protect your data.
            </p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 20px 0; background-color: white; border: 1px solid #e0e0e0; border-radius: 6px;">
              <tr>
                <td style="padding: 16px;">
                  <p style="margin: 0 0 10px 0; font-weight: 600; color: #dc3545; font-size: 14px;">🚨 Detected Activity:</p>
                  <ul style="margin: 0; padding-left: 20px; color: #333; font-size: 14px; line-height: 1.8;">
                    <li>Multiple failed login attempts from unknown location</li>
                    <li>IP Address: ${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}</li>
                    <li>Timestamp: ${new Date().toLocaleString()}</li>
                  </ul>
                </td>
              </tr>
            </table>
            <p style="margin: 0 0 20px 0; color: #333; font-size: 15px; line-height: 1.6;">
              To restore full access to your account, please verify your identity within the next <strong>2 hours</strong>.
            </p>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
              <tr>
                <td style="background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%); border-radius: 6px;">
                  <a href="[CLICK_LINK]" style="display: inline-block; padding: 16px 40px; color: white; text-decoration: none; font-size: 16px; font-weight: 700;">
                    Verify Identity Now
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin: 0; color: #856404; font-size: 13px; line-height: 1.5; background-color: #fff3cd; padding: 12px; border-radius: 4px;">
              <strong>⚠️ Warning:</strong> Failure to verify your identity within the specified timeframe may result in permanent account suspension.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding-top: 25px;">
            <p style="margin: 0; color: #888; font-size: 12px; line-height: 1.5;">
              Corporate Security Operations Center<br/>
              24/7 Security Hotline: 1-800-SEC-HELP
            </p>
          </td>
        </tr>
      </table>
    `,
  },
  it_support: {
    subject: "IT Department: Mandatory Security Update Required",
    body: `
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="padding-bottom: 25px; border-bottom: 3px solid #0078d4;">
            <table role="presentation" cellspacing="0" cellpadding="0">
              <tr>
                <td style="background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%); padding: 12px 20px; border-radius: 6px;">
                  <span style="color: white; font-size: 16px; font-weight: 600;">🖥️ IT SUPPORT</span>
                </td>
                <td style="padding-left: 15px;">
                  <span style="color: #666; font-size: 13px;">Ticket #ITS-${Math.floor(Math.random() * 90000) + 10000}</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding: 30px 0;">
            <h2 style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 20px; font-weight: 600;">Mandatory Security Patch Installation</h2>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">Hello [TARGET_NAME],</p>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">
              As part of our ongoing security compliance initiative, the IT Department requires all employees to install a critical security update. This update addresses recently discovered vulnerabilities in our corporate systems.
            </p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0; background-color: #e7f3ff; border-left: 4px solid #0078d4; border-radius: 0 4px 4px 0;">
              <tr>
                <td style="padding: 20px;">
                  <p style="margin: 0 0 12px 0; font-weight: 600; color: #0078d4; font-size: 14px;">📋 Update Details:</p>
                  <ul style="margin: 0; padding-left: 20px; color: #333; font-size: 14px; line-height: 1.8;">
                    <li>Security Patch Version: SP-2024.${Math.floor(Math.random() * 12) + 1}.${Math.floor(Math.random() * 30) + 1}</li>
                    <li>Estimated Installation Time: 5-10 minutes</li>
                    <li>Deadline: End of business today</li>
                    <li>Restart Required: Yes</li>
                  </ul>
                </td>
              </tr>
            </table>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 30px 0;">
              <tr>
                <td style="background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%); border-radius: 6px;">
                  <a href="[CLICK_LINK]" style="display: inline-block; padding: 14px 32px; color: white; text-decoration: none; font-size: 15px; font-weight: 600;">
                    Download Security Update →
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin: 0; color: #666; font-size: 13px; line-height: 1.5;">
              Please save all work before proceeding with the installation. If you experience any issues, contact the IT Help Desk at extension 4357.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding-top: 25px; border-top: 1px solid #e0e0e0;">
            <table role="presentation" cellspacing="0" cellpadding="0">
              <tr>
                <td style="padding-right: 15px;">
                  <p style="margin: 0; color: #333; font-size: 13px; font-weight: 600;">IT Help Desk</p>
                  <p style="margin: 2px 0 0 0; color: #666; font-size: 12px;">helpdesk@company.com</p>
                </td>
                <td style="border-left: 1px solid #e0e0e0; padding-left: 15px;">
                  <p style="margin: 0; color: #333; font-size: 13px;">Ext: 4357</p>
                  <p style="margin: 2px 0 0 0; color: #666; font-size: 12px;">Mon-Fri 8AM-6PM</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    `,
  },
  ceo_fraud: {
    subject: "Quick Favor - Confidential",
    body: `
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="padding: 10px 0;">
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">[TARGET_NAME],</p>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">
              Are you available right now? I'm tied up in a board meeting but need you to handle something important for me.
            </p>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">
              There's a time-sensitive matter that requires immediate attention. I can't call right now, but I need you to review the details and take action ASAP.
            </p>
            <p style="margin: 0 0 20px 0; color: #333; font-size: 15px; line-height: 1.6;">
              Please click below to access the confidential request:
            </p>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
              <tr>
                <td style="background-color: #1a1a1a; border-radius: 6px;">
                  <a href="[CLICK_LINK]" style="display: inline-block; padding: 12px 28px; color: white; text-decoration: none; font-size: 14px; font-weight: 500;">
                    View Confidential Request
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin: 0 0 8px 0; color: #333; font-size: 15px; line-height: 1.6;">
              Let me know once it's handled. I'll be in meetings until 5pm.
            </p>
            <p style="margin: 20px 0 0 0; color: #333; font-size: 15px;">
              Thanks,<br/>
              <strong>John Mitchell</strong><br/>
              <span style="color: #666; font-size: 13px;">Chief Executive Officer</span>
            </p>
            <p style="margin: 20px 0 0 0; color: #888; font-size: 12px; font-style: italic;">
              Sent from my iPhone
            </p>
          </td>
        </tr>
      </table>
    `,
  },
  custom: {
    subject: "Important: Action Required",
    body: `
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="padding: 10px 0;">
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">Dear [TARGET_NAME],</p>
            <p style="margin: 0 0 16px 0; color: #333; font-size: 15px; line-height: 1.6;">
              This is a custom phishing simulation template. Edit this content to create your own realistic scenario for security awareness training.
            </p>
            <p style="margin: 0 0 20px 0; color: #333; font-size: 15px; line-height: 1.6;">
              <strong>Tips for creating effective templates:</strong>
            </p>
            <ul style="margin: 0 0 20px 0; padding-left: 20px; color: #333; font-size: 14px; line-height: 1.8;">
              <li>Use urgency or authority to create pressure</li>
              <li>Include realistic company branding</li>
              <li>Reference current events or internal projects</li>
              <li>Keep the call-to-action prominent</li>
            </ul>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
              <tr>
                <td style="background-color: #6c757d; border-radius: 6px;">
                  <a href="[CLICK_LINK]" style="display: inline-block; padding: 12px 28px; color: white; text-decoration: none; font-size: 14px; font-weight: 500;">
                    Take Action →
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    `,
  },
};

serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { type, companyName, targetName }: TemplateRequest = await req.json();

    console.log(`Generating template: ${type}`);

    const template = templates[type] || templates.custom;

    let body = template.body;
    if (companyName) {
      body = body.replace(/Company/g, companyName);
    }

    console.log(`Template generated successfully: ${type}`);

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
