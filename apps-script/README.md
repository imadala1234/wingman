# WingMan push server (Google Apps Script)

Runs on your Google account (free). It receives your upcoming flights from the app, checks live status every 10 minutes and sends Web Push alerts to your phone.

1. Go to script.google.com → **New project**. Name it `WingMan push`.
2. Delete the sample code, paste all of `Code.gs`, and save.
3. In the function dropdown pick **setup** and click **Run**. Approve the permissions (Google may show "unverified app": Advanced → Go to WingMan push). This creates the 10-minute timer and your push keys.
4. **Deploy → New deployment → Web app.** Execute as: **Me**. Who has access: **Anyone**. Deploy and copy the web app URL (ends in `/exec`).
5. In WingMan: Settings → Push alerts → paste the URL → **Turn on push alerts**. Open WingMan from the Home Screen icon (iOS 16.4 or later).

If you change the code later: Deploy → Manage deployments → edit → New version.
