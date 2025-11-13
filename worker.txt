const UPSTREAM_DNS_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query",
  "https://dns.quad9.net/dns-query",
  "https://doh.opendns.com/dns-query",
];

const DNS_CACHE_TTL = 300;
const REQUEST_TIMEOUT = 10000;
const MAX_RETRIES = 3;
const RATE_LIMIT_REQUESTS = 100;
const RATE_LIMIT_WINDOW = 60000;
const MAX_POST_SIZE = 4096;

const rateLimitMap = new Map();

// ============================
// Event Listener
// ============================
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

// ============================
// Main Request Handler
// ============================
async function handleRequest(request) {
  const url = new URL(request.url);

  if (url.pathname === "/apple") {
    return generateAppleProfile(request.url);
  }

  const clientIP =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown";

  if (!checkRateLimit(clientIP)) {
    return new Response("Rate limit exceeded. Please try again later.", {
      status: 429,
      headers: {
        "Content-Type": "text/plain",
        "Retry-After": "60",
      },
    });
  }

  if (url.pathname !== "/dns-query") {
    return new Response(getHomePage(request.url), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
      },
    });
  }

  if (request.method === "OPTIONS") {
    return handleOptions();
  }

  try {
    let dnsResponse;

    if (request.method === "GET") {
      dnsResponse = await handleGetRequest(url);
    } else if (request.method === "POST") {
      dnsResponse = await handlePostRequest(request);
    } else {
      return new Response("Method not allowed", {
        status: 405,
        headers: {
          Allow: "GET, POST, OPTIONS",
        },
      });
    }

    return buildClientResponse(dnsResponse);
  } catch (error) {
    console.error("Error:", error);
    return new Response("DNS query failed: " + error.message, {
      status: 500,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

// ============================
// Generate Apple MobileConfig
// ============================
function generateAppleProfile(requestUrl) {
  const baseUrl = new URL(requestUrl);
  const dohUrl = `${baseUrl.protocol}//${baseUrl.hostname}/dns-query`;
  const hostname = baseUrl.hostname;

  const profileUUID = crypto.randomUUID();
  const dnsPayloadUUID = crypto.randomUUID();

  const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
    <key>PayloadContent</key>
    <array>
      <dict>
        <key>PayloadType</key>
        <string>com.apple.dns.proxy</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadIdentifier</key>
        <string>com.cloudflare.doh.${dnsPayloadUUID}</string>
        <key>PayloadUUID</key>
        <string>${dnsPayloadUUID}</string>
        <key>DNSProxyConfigurations</key>
        <array>
          <dict>
            <key>DNSProxyServerAddress</key>
            <string>${dohUrl}</string>
            <key>DNSProxyServerPort</key>
            <integer>443</integer>
            <key>DNSProxyLocal</key>
            <true/>
            <key>PayloadUUID</key>
            <string>${crypto.randomUUID()}</string>
          </dict>
        </array>
      </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.cloudflare.doh.profile.${profileUUID}</string>
    <key>PayloadUUID</key>
    <string>${profileUUID}</string>
    <key>PayloadDisplayName</key>
    <string>DoH Proxy</string>
  </dict>
  </plist>`;

  return new Response(mobileconfig, {
    status: 200,
    headers: {
      "Content-Type": "application/x-apple-aspen-config; charset=utf-8",
      "Content-Disposition": `attachment; filename="doh-proxy-${hostname}.mobileconfig"`,
      "Cache-Control": "no-cache",
    },
  });
}

// ============================
// GET handler
// ============================
async function handleGetRequest(url) {
  const dnsParam = url.searchParams.get("dns");

  if (!dnsParam) throw new Error("Missing dns parameter");
  if (!isValidBase64Url(dnsParam))
    throw new Error("Invalid dns parameter format");

  for (let i = 0; i < UPSTREAM_DNS_PROVIDERS.length; i++) {
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const upstreamUrl = new URL(UPSTREAM_DNS_PROVIDERS[i]);
        upstreamUrl.searchParams.set("dns", dnsParam);

        url.searchParams.forEach((value, key) => {
          if (key !== "dns") upstreamUrl.searchParams.set(key, value);
        });

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        const response = await fetch(upstreamUrl.toString(), {
          method: "GET",
          headers: {
            Accept: "application/dns-message",
            "User-Agent": "DoH-Proxy-Worker/1.0",
          },
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (response.ok) return response;
      } catch (err) {
        if (
          i === UPSTREAM_DNS_PROVIDERS.length - 1 &&
          attempt === MAX_RETRIES - 1
        )
          throw err;
      }
    }
  }
  throw new Error("All upstream DNS servers failed");
}

// ============================
// POST handler
// ============================
async function handlePostRequest(request) {
  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.startsWith("application/dns-message")) {
    throw new Error("Invalid Content-Type. Expected application/dns-message");
  }

  const body = await request.arrayBuffer();
  if (body.byteLength === 0 || body.byteLength > MAX_POST_SIZE) {
    throw new Error("Invalid DNS message size");
  }

  for (let i = 0; i < UPSTREAM_DNS_PROVIDERS.length; i++) {
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        const response = await fetch(UPSTREAM_DNS_PROVIDERS[i], {
          method: "POST",
          headers: {
            "Content-Type": "application/dns-message",
            Accept: "application/dns-message",
            "User-Agent": "DoH-Proxy-Worker/1.0",
          },
          body: body,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (response.ok) return response;
      } catch (err) {
        if (
          i === UPSTREAM_DNS_PROVIDERS.length - 1 &&
          attempt === MAX_RETRIES - 1
        )
          throw err;
      }
    }
  }
  throw new Error("All upstream DNS servers failed");
}

// ============================
// Build Client Response
// ============================
function buildClientResponse(upstreamResponse) {
  const headers = new Headers(upstreamResponse.headers);

  [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
  ].forEach((h) => headers.delete(h));

  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  headers.set("Cache-Control", `public, max-age=${DNS_CACHE_TTL}`);
  headers.set("Content-Type", "application/dns-message");

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    headers,
  });
}

// ============================
// Options (CORS preflight)
// ============================
function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  });
}

// ============================
// Rate Limit
// ============================
function checkRateLimit(clientIP) {
  const now = Date.now();
  const clientData = rateLimitMap.get(clientIP);

  if (!clientData || now > clientData.resetTime) {
    rateLimitMap.set(clientIP, {
      count: 1,
      resetTime: now + RATE_LIMIT_WINDOW,
    });
    return true;
  }

  if (clientData.count >= RATE_LIMIT_REQUESTS) return false;

  clientData.count++;
  return true;
}

// ============================
// Base64URL Validation
// ============================
function isValidBase64Url(str) {
  return /^[A-Za-z0-9_-]+=?=?$/.test(str);
}

// ============================
// HTML Homepage
// ============================
function getHomePage(requestUrl) {
  return `
<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>DoH Proxy</title>
    <!-- Bootstrap 5 RTL -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.rtl.min.css"
      rel="stylesheet"
    />
    <!-- Bootstrap Icons -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"
      rel="stylesheet"
    />
    <style>
      body {
        background: linear-gradient(135deg, #0f172a, #1e293b);
        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        color: #f8f9fa;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
      }

      .card {
        border-radius: 1rem;
        background: linear-gradient(135deg, #1e293b, #334155);
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
        max-width: 600px;
        margin: 50px auto 20px auto;
      }

      h1 {
        text-shadow: 0 0 10px rgba(96, 165, 250, 0.7);
        font-size: 2rem;
      }

      pre {
        background: #0f172a;
        color: #22d3ee;
        padding: 15px;
        border-radius: 0.5rem;
        font-size: 1rem;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-word;
        border: 1px solid #1e40af;
        direction: ltr;
        text-align: left;
      }

      .btn-primary,
      .btn-success {
        border-radius: 0.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
      }

      .btn-primary:hover,
      .btn-success:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 123, 255, 0.5);
      }

      .alert-custom {
        background: rgba(16, 185, 129, 0.1);
        color: #1e94af;
        border-left: 5px solid #10b981;
        padding: 15px;
        border-radius: 0.5rem;
        font-size: 0.95rem;
        margin-top: 20px;
      }

      footer {
        text-align: center;
        margin-top: auto;
        padding: 20px;
        background: linear-gradient(135deg, #1e293b, #0f172a);
        color: #a5b4fc;
        font-size: 0.9rem;
        border-top: 1px solid #334155;
      }

      p {
        color: #1e94af;
      }

      footer a {
        color: #22d3ee;
        text-decoration: none;
        font-weight: 600;
      }

      footer a:hover {
        text-decoration: underline;
      }
    </style>
  </head>
  <body>
    <div class="card p-4 text-center" style="max-width: 700px">
      <h1 class="mb-4">
        <i class="bi bi-shield-lock-fill"></i> DNS over HTTPS
      </h1>
      <p class="mb-3">
        Copy your DoH link below and use it in your browser or iOS client:
      </p>

      <pre id="dohUrl">${new URL(requestUrl).protocol}//${
    new URL(requestUrl).hostname
  }/dns-query</pre>


      <button class="btn btn-primary my-3" onclick="copyToClipboard()">
        <i class="bi bi-clipboard-fill"></i> Copy Link
      </button>

      <p class="mb-2">For iOS, download and install the profile below:</p>
      <a href="/apple" download class="btn btn-success btn-lg mb-3">
        <i class="bi bi-apple"></i> Download iOS Profile
      </a>

      <div class="alert-custom text-center">
        <i class="bi bi-info-circle-fill"></i>
        Installing this profile enables DNS-over-HTTPS on your device and
        secures your DNS queries. VPN is required to access blocked websites.
      </div>
    </div>

    <footer>
      <p>
        Powered by with <a class="heart">&hearts;</a> by
        <a href="" target="_blank">AmiN</a>
        &copy; 2025
      </p>
    </footer>

    <script>
      function copyToClipboard() {
        const text = document.getElementById("dohUrl").textContent.trim();
        navigator.clipboard
          .writeText(text)
          .then(() => alert("Link copied successfully!"))
          .catch(() => alert("Failed to copy, try again."));
      }
    </script>
  </body>
</html>

`;
}

