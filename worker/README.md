# WingMan push server

A small Cloudflare Worker (free tier) that sends push alerts when WingMan is closed.
It never holds your Google data. It receives only your upcoming flight numbers, times, gate info and alert settings from the app.

## Set up (about 10 minutes, all in the Cloudflare dashboard)

1. Sign up free at dash.cloudflare.com.
2. **Workers & Pages → Create → Create Worker.** Name it `wingman-push`, click Deploy, then **Edit code**. Replace everything with the contents of `worker/index.js` and click Deploy.
3. **Storage & Databases → KV → Create namespace** named `WM`.
4. Open the Worker → **Settings → Bindings → Add → KV namespace.** Variable name `WM`, pick the `WM` namespace.
5. Worker → **Settings → Variables and Secrets → Add** (type Secret) these three:
   - `ADB_KEY`: your AeroDataBox / RapidAPI key
   - `VAPID_JWK`: the private key JSON given to you in chat (keep it private; never commit it)
   - `VAPID_SUBJECT`: `mailto:sm466991234@gmail.com`
6. Worker → **Settings → Triggers → Cron Triggers → Add** `*/10 * * * *`.
7. Copy the Worker address (like `https://wingman-push.<name>.workers.dev`). Opening it in a browser should show `{"ok":true,...,"adbKey":true}`.
8. In WingMan: Settings → Push alerts → paste the address → **Turn on push alerts**. You must open WingMan from the Home Screen icon (iPhone iOS 16.4 or later).

Alerts: delays (5 min or more), cancellations, gate and terminal changes, check-in open, time to leave, boarding soon.
