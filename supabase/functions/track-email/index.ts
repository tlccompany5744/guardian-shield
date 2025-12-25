import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const targetId = url.searchParams.get("tid");
  const action = url.searchParams.get("action");
  const redirect = url.searchParams.get("redirect");

  console.log(`Tracking event: ${action} for target ${targetId}`);

  if (!targetId || !action) {
    return new Response("Missing parameters", { status: 400 });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const now = new Date().toISOString();

    if (action === "open") {
      // Update opened status
      await supabase
        .from("campaign_targets")
        .update({ 
          status: "opened", 
          opened_at: now 
        })
        .eq("id", targetId)
        .neq("status", "clicked"); // Don't downgrade from clicked

      // Return 1x1 transparent pixel
      const pixel = new Uint8Array([
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
        0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
        0x01, 0x00, 0x3b
      ]);

      return new Response(pixel, {
        status: 200,
        headers: {
          "Content-Type": "image/gif",
          "Cache-Control": "no-cache, no-store, must-revalidate",
        },
      });
    } else if (action === "click") {
      // Update clicked status
      await supabase
        .from("campaign_targets")
        .update({ 
          status: "clicked", 
          clicked_at: now,
          opened_at: now // Also mark as opened if not already
        })
        .eq("id", targetId);

      // Redirect to education page or specified URL
      const educationPage = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Security Awareness Training</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { 
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              padding: 20px;
            }
            .container {
              background: white;
              border-radius: 16px;
              padding: 40px;
              max-width: 600px;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            .icon {
              width: 80px;
              height: 80px;
              background: #ff6b35;
              border-radius: 50%;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0 auto 24px;
              font-size: 40px;
            }
            h1 { 
              color: #1a1a2e; 
              text-align: center;
              margin-bottom: 16px;
              font-size: 28px;
            }
            .subtitle {
              color: #666;
              text-align: center;
              margin-bottom: 32px;
              font-size: 18px;
            }
            .info-box {
              background: #f8f9fa;
              border-left: 4px solid #ff6b35;
              padding: 20px;
              margin-bottom: 24px;
              border-radius: 0 8px 8px 0;
            }
            .info-box h3 {
              color: #ff6b35;
              margin-bottom: 8px;
            }
            .tips {
              list-style: none;
              padding: 0;
            }
            .tips li {
              padding: 12px 0;
              border-bottom: 1px solid #eee;
              display: flex;
              align-items: flex-start;
              gap: 12px;
            }
            .tips li:last-child { border-bottom: none; }
            .check { color: #22c55e; font-size: 20px; }
            .footer {
              text-align: center;
              margin-top: 24px;
              color: #888;
              font-size: 14px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="icon">🎯</div>
            <h1>You Clicked a Simulated Phishing Link!</h1>
            <p class="subtitle">This was a security awareness training exercise</p>
            
            <div class="info-box">
              <h3>⚠️ What Just Happened?</h3>
              <p>You clicked a link in a simulated phishing email. In a real attack, this could have led to credential theft, malware installation, or data breach.</p>
            </div>
            
            <h3 style="margin-bottom: 16px;">🛡️ How to Spot Phishing Emails:</h3>
            <ul class="tips">
              <li><span class="check">✓</span> <span>Check the sender's email address carefully - look for misspellings</span></li>
              <li><span class="check">✓</span> <span>Hover over links before clicking to see the actual URL</span></li>
              <li><span class="check">✓</span> <span>Be suspicious of urgent language or threats</span></li>
              <li><span class="check">✓</span> <span>Never enter credentials from an email link - go directly to the website</span></li>
              <li><span class="check">✓</span> <span>Report suspicious emails to your security team</span></li>
            </ul>
            
            <p class="footer">
              This simulation was conducted by your security team to improve awareness.<br/>
              No data was collected. Stay vigilant! 🔐
            </p>
          </div>
        </body>
        </html>
      `;

      return new Response(educationPage, {
        status: 200,
        headers: {
          "Content-Type": "text/html",
          ...corsHeaders,
        },
      });
    }

    return new Response("Invalid action", { status: 400 });
  } catch (error: any) {
    console.error("Tracking error:", error);
    return new Response("Error", { status: 500 });
  }
});
