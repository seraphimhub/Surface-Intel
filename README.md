#  Surface Intel — Headless Recon Framework

<p align="center">
<img width="500" height="500" alt="ok" src="https://github.com/user-attachments/assets/a185c58c-cbc0-49ab-9c59-ed2c528314a2" />

### Surface Intel is a Python-based reconnaissance tool designed for deep attack surface mapping using a combination of crawling, JavaScript analysis, and headless browser automation.

### This framework focuses on high-value endpoint discovery to help bug bounty hunters and penetration testers uncover hidden functionality in modern web applications.

 **Features**

 **Headless Browser Intelligence (Playwright)** 
- Captures real network requests/responses from modern web apps (SPA)
- Reveals endpoints not visible through static analysis
  
 **Advanced JavaScript Endpoint Extraction**

Parses JavaScript files to extract :

- API endpoints

- Hidden routes

- Absolute URLs

 **Wayback Surface Discovery**

- Retrieves historical endpoints from Wayback Machine

- Helps uncover forgotten or deprecated endpoints

 **Smart Endpoint Scoring**

Prioritizes endpoints based on sensitive keywords:

- auth, payment, user, wallet, etc.
  
- Automatically filters out noise
  
 **Structured Report Output**

- Generates clean .md reports
  
Categorized into:

- API
  
- HTML
  
- JS assets
  
- Others
  
 **Lightweight Validation Engine**

- Validates endpoints without being overly noisy
  
- Safe for bug bounty environments

 **Use Cases**
- Bug bounty reconnaissance (hybrid manual + automation)
- Attack surface mapping for modern applications
  
Discovering:

- Hidden APIs
  
- Internal endpoints
  
- Sensitive functionalities
  
Ideal for:

- React / Next.js / SPA-based applications


 **Requirements**
```
pip install requests beautifulsoup4
pip install playwright
playwright install chromium
```

 **Usage**
```
python3 surface_intel.py -t https://target.com
```
 **Output**


Automatically generates a report file:

```
surface-intel-report-YYYYMMDD-HHMMSS.md
```
Report includes:

- Discovered endpoints
- Response status & metadata
- Priority scoring
- Classification
  
 **Disclaimer**

This tool is intended for:

- Authorized security testing
- Bug bounty programs
- Research and educational purposes

Any misuse is the responsibility of the user.

 **Tagline**

> “Map the surface. Extract the intel.”
