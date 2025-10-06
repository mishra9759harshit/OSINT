
# Nightmare Pro OSINT Toolkit

![Nightmare Pro Banner](https://img.shields.io/badge/Nightmare%20Pro-OSINT-ff0000?style=for-the-badge)

**Author:** [Harshit Mishra](https://github.com/mishra9759harshit)  
**Repository:** [OSINT](https://github.com/mishra9759harshit/OSINT)  
**Release:** 2025  

---

## ⚡ Overview

**Nightmare Pro** is an **advanced, scalable OSINT (Open-Source Intelligence) toolkit** designed for passive reconnaissance. It is optimized to run on **Termux / Linux** environments and allows analysts, penetration testers, and cybersecurity enthusiasts to gather intelligence from emails, phone numbers, domains, and usernames without active scanning—unless explicitly enabled.

This toolkit integrates multiple APIs, public databases, and open-source tools, providing a **full intelligence workflow** in a single, automated script.

---

## 🛠 Features

- **Passive Reconnaissance**
  - Email breach checks via [Have I Been Pwned](https://haveibeenpwned.com/)
  - Email verification with Hunter.io and EmailRep
  - Gravatar profile checks
  - Phone number verification via Numverify

- **Domain & Network Intelligence**
  - WHOIS and DNS lookups
  - Shodan host intelligence (requires API key)
  - TheHarvester domain reconnaissance
  - Google dork tips automation

- **Social Media & Username Recon**
  - Sherlock username scans across 300+ social platforms
  - Google dorking tips for usernames

- **Optional Active Scans**
  - Nmap TCP/Service scans (permission required)

- **Output & Reporting**
  - CSV and HTML summaries
  - Organized output folders per target type
  - Reverse image search tips & Google dork automation

- **Extensible & Automated**
  - Reads API keys from `.env` automatically
  - Automatic dependency checks & Termux/Linux support
  - Modular design for adding new intelligence sources

---

## 📥 Installation (Termux/Linux)

```bash
# Clone repository
git clone https://github.com/mishra9759harshit/OSINT.git
cd OSINT

# Make the script executable
chmod +x nightmare_pro.sh

# Optional: create .env file with your API keys
nano .env
# Example .env:
# HIBP_API_KEY="..."
# HUNTER_API_KEY="..."
# SHODAN_API_KEY="..."
# NUMVERIFY_API_KEY="..."
# EMAILREP_API_KEY="..."


---

⚙ Usage Examples

# Email OSINT
./nightmare_pro.sh --email someone@example.com

# Phone OSINT
./nightmare_pro.sh --phone "+919876543210"

# Domain OSINT
./nightmare_pro.sh --domain example.com

# Username OSINT
./nightmare_pro.sh --username targetuser

# Enable active nmap scans (only with permission)
./nightmare_pro.sh --domain example.com --enable-active

# Install missing dependencies automatically
./nightmare_pro.sh --install-deps


---

🧩 Output

Organized folders:

email/, phone/, domain/, username/


Summary reports:

summary.csv

summary_<timestamp>.html


Logs:

run_<timestamp>.log


Reverse image search and Google dork tips saved as text files



---

🔐 Security & Ethics

Nightmare Pro performs mostly passive intelligence gathering. Active scans and unauthorized probing are illegal without permission. Use this toolkit responsibly and follow local laws and terms of service.


---

🌐 Supported APIs & Tools

Have I Been Pwned

Hunter.io

EmailRep

Numverify

Shodan

TheHarvester

Sherlock

Whois, Dig, Nmap

ExifTool (optional)



---

🚀 Contribution

Contributions, bug reports, and suggestions are welcome. Feel free to open issues or pull requests.


---

📜 License

Distributed under the MIT License. See LICENSE for details.


---

👤 Author

Harshit Mishra – GitHub
Cybersecurity & OSINT Enthusiast | Passionate about automation & intelligence gathering


---

🔗 Links

GitHub Repository

Have I Been Pwned

Hunter.io

Shodan

Sherlock


---
