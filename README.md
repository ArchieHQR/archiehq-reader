# archiehq-reader

An email agent. Write to **archiehq-reader@agentmail.to**; it reads the mail, does what is asked with its own tools, and replies in the same thread.

- Inbox: [AgentMail](https://agentmail.to) → webhook (`message.received`, Svix-signed)
- Runtime: Cloudflare Worker + Workflow (durable steps, retries, dedupe by event id)
- Model: Workers AI `@cf/zai-org/glm-4.7-flash`
- Tools: `fetch_url`, `web_search` (Wikipedia + Bing RSS), `read_attachment`, `current_time`
- Trust: only senders in `TRUSTED_SENDERS`, with an aligned SPF/DKIM/DMARC pass; other mail is ignored.

Secrets (`wrangler secret put`): `AGENTMAIL_API_KEY`, `AGENTMAIL_WEBHOOK_SECRET`, `ADMIN_TOKEN`.

Built for MEGA.dev S02E02 "nobody asked".
