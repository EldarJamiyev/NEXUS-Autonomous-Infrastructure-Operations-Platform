# ChatOps guide

Set `CHATOPS_PROVIDER=discord` or `slack` and `CHATOPS_WEBHOOK_URL` (an incoming-webhook URL) in `.env`, then
restart. Without them, every message is still recorded and shown on the ChatOps page as **DRY_RUN** - NEXUS never
claims delivery it did not make. Delivery failures are recorded with the HTTP error.

Messages: `AUTOHEAL EVENT` (verified fix), `AUTOHEAL FAILED` (verification failed, rollback status, human action
required), `APPROVAL REQUIRED`, and test notifications (ChatOps page → *Send test notification*).

```
AUTOHEAL EVENT

Alert:        NginxDown (INC-0011)
Target:       LINUX01
Detected:     16:44:10
Action:       Restart nginx
Verification: HTTP 200 (GET /healthz -> 200 OK (nginx))
Result:       RESOLVED
Human action: NOT REQUIRED
```
Treat the webhook URL as a secret: it is read from the environment and never returned by the API.
