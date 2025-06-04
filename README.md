## ⚙ Technologies Used
- *OpenCTI* — Threat Intelligence Platform
- *PyCTI* — Python API for OpenCTI
- *Python* — Data parsing and automation scripts
- *ModSecurity* — Open Source Web Application Firewall
- *NGINX* — Web server and reverse proxy
- *Telegram Bot API* — For alert notifications
- *Docker* — For service orchestration

## 🛠 Configuration

### 1. Clone this repository
```bash
git clone https://github.com/nikolkol/ANGuard-Thesis.git
cd ANGuard-Thesis
```

### 2. Edit .env file inside folder OpenCTI

### 3. Deploy OpenCTI locally
```bash
cd opencti
docker-compose up -d
```

### 4. Start WAF Environment (NGINX + ModSecurity + DVWA)
```bash
cd DVWA-nginx-ModSecurity
docker-compose up -d
```

### 5. Run ANGuard Parser
```bash
cd DVWA-nginx-ModSecurity/script
python import_logging.py
```

### 6. Run ANGuard Parser
```bash
python import_logging.py
```
### 7. Configure Telegram Bot for Alerts 
1. Make bot at BotFather and copy the token.
2. Add TELEGRAM_TOKEN and TELEGRAM_CHAT_ID to  .env file.
3. Make sure webhook alert is activated inside file import_logging.py.

### 8. Run Telegram Alert Script
```bash
cd DVWA-nginx-ModSecurity/script
python modsec-logging-tele-1.py
```
