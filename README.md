# Ghost Core 👻

Invisible Burn-After-Reading Temporary Admin Access for WordPress.

Ghost Core is an advanced temporary admin access system built for developers, agencies, and support teams who need secure, stealthy, and disposable WordPress access links without creating visible administrator accounts.

Unlike traditional temporary login plugins, Ghost Core operates through a hidden system layer with granular capability injection, forensic logging, Telegram alerts, and one-click session destruction.

---

# Features

* 🔥 True burn-after-reading access tokens
* 👻 Invisible system user
* 🔐 Granular capability-based access
* 🧠 Plugin-aware permission grouping
* ☠️ One-click session kill switch
* 📱 Telegram security alerts
* 🧬 Browser fingerprint validation
* 🌍 IP locking & hijack detection
* 📋 Forensic logging
* 🚫 Hidden from REST API and user lists
* ⚡ Lightweight pure PHP architecture

---

# Why Ghost Core?

Most temporary login plugins:

* create visible administrator users
* clutter your database
* rely on heavy plugin frameworks
* leave expired users behind
* expose accounts through APIs

Ghost Core avoids all of that.

It uses:

* one hidden system account
* temporary capability overlays
* self-destructing access tokens
* live session validation

---

# Ghost Core vs Traditional Temporary Login Plugins

| Feature                   | Traditional Plugins | Ghost Core |
| ------------------------- | ------------------- | ---------- |
| Real User Creation        | Yes                 | No         |
| Hidden System Layer       | No                  | Yes        |
| Burn-After-Reading Tokens | No                  | Yes        |
| Telegram Alerts           | Paid/Unavailable    | Built-in   |
| Session Kill Switch       | Limited             | Yes        |
| REST API Hidden           | No                  | Yes        |
| Browser Fingerprinting    | No                  | Yes        |
| Granular Capabilities     | Limited             | Yes        |
| Database Bloat            | Common              | Minimal    |

---

# Installation

1. Download the repository ZIP
2. Upload to:
   `/wp-content/plugins/`
3. Activate Ghost Core
4. Open:
   `Tools → Ghost Access`

---

# Telegram Alerts Setup

1. Open Telegram
2. Search for `@BotFather`
3. Create a new bot using:
   `/newbot`
4. Copy your bot token
5. Get your Chat ID using:
   `@userinfobot`

Build URL:

https://api.telegram.org/botTOKEN/sendMessage?chat_id=CHAT_ID

Paste inside:

Tools → Ghost Access → Telegram Bot Alert URL

---

# Security Notes

Ghost Core is designed for experienced WordPress developers and administrators.

Always:

* use HTTPS
* limit token expiry
* enable IP locking
* revoke sessions after support completion

---

# Disclaimer

This project is provided for educational and administrative purposes only.

Use responsibly.

---

# Author

Developed by Chavinesh Mukund

