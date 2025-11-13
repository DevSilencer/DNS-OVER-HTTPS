# 🔒 Secure DoH Proxy

A lightweight, secure, and performance-optimized **DNS-over-HTTPS (DoH)** proxy built for **Cloudflare Workers**.  
This worker allows clients to perform encrypted DNS lookups using standard DoH queries, ensuring privacy, reliability, and performance.

---

## 🚀 Features

- **Secure DNS Resolution:** Encrypts all DNS queries using HTTPS.
- **Smart Retry Logic:** Automatically retries failed DNS requests up to `MAX_RETRIES` times.
- **Timeout Protection:** Aborts DNS queries exceeding `REQUEST_TIMEOUT` (default: 10 seconds).
- **Caching Layer:** Caches successful DNS responses for `DNS_CACHE_TTL` seconds to reduce latency and upstream load.
- **Rate Limiting:** Limits clients to `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW` (default: 100 req / 60s).
- **Payload Validation:** Restricts POST request body size to a safe maximum of `MAX_POST_SIZE` bytes.
- **Fully Serverless:** Runs efficiently on Cloudflare’s global edge network.

---

## ⚙️ Configuration Constants

| Constant | Description | Default |
|-----------|-------------|----------|
| `DNS_CACHE_TTL` | Cache lifetime for DNS responses (in seconds) | `300` |
| `REQUEST_TIMEOUT` | Max duration to wait for an upstream DNS response (in ms) | `10000` |
| `MAX_RETRIES` | Number of retry attempts for failed queries | `3` |
| `RATE_LIMIT_REQUESTS` | Max requests allowed per rate window | `100` |
| `RATE_LIMIT_WINDOW` | Time window for rate limiting (in ms) | `60000` |
| `MAX_POST_SIZE` | Maximum allowed POST body size (in bytes) | `4096` |

---

## 🧠 How It Works

1. The Worker receives an incoming DoH request (either GET or POST).  
2. It validates the request format and ensures payload size and rate limit constraints.  
3. The query is forwarded to a trusted upstream DoH resolver (e.g., Cloudflare or Google DNS).  
4. The response is cached for `DNS_CACHE_TTL` seconds to speed up future requests.  
5. Results are returned to the client in standard DoH JSON or binary format.

---


---

## 🛠 Deployment

1. Clone or copy your worker code.  
2. Log in to Cloudflare and open the **Workers Dashboard**.  
3. Create a new Worker and paste your DoH proxy script.  
4. Deploy and note the public URL of your Worker.  
5. (Optional) Bind a custom domain or subdomain.

---

