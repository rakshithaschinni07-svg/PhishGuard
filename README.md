PhishGuard

Rule-Based URL Security Scanner

PhishGuard is a defensive cybersecurity web application that analyzes website URLs using rule-based security indicators and assigns a risk score.

The project is designed for educational purposes and security awareness. It helps users understand why a URL may require further review.

---

Features

- URL validation
- Rule-based URL scanning
- Risk scoring
- Low, Medium and High risk classification
- Detection of suspicious URL indicators
- Scan history
- Scan details
- Analytics dashboard
- Detection rules/settings page
- Exportable scan reports
- SQLite database for storing scan history
- Responsive web interface

---

Detection Rules

PhishGuard currently checks for:

1. @ Symbol — +2
2. Multiple Hyphens — +1
3. Security-related Keywords — +1
4. Long URL — +1
5. HTTP Connection — +1
6. IP Address — +2
7. Non-standard Port — +1
8. Multiple Subdomains — +1
9. Unusual Domain Characters — +1

---

Risk Classification

Score| Risk Level| Result
0| Low| No Obvious Warning
1–2| Medium| Needs Review
3+| High| Potentially Suspicious

---

Technologies Used

Frontend

- HTML
- CSS

Backend

- Python
- Flask

Database

- SQLite

Template Engine

- Jinja2

---

Project Structure

PHISHGUARD/
│
├── static/
│   └── style.css
│
├── templates/
│   ├── analytics.html
│   ├── history.html
│   ├── index.html
│   ├── scan_details.html
│   ├── scanner.html
│   └── settings.html
│
├── venv/
├── app.py
├── phishguard.db
├── requirements.txt
└── README.md

---

How It Works

1. URL Validation

The application first checks whether the entered URL uses "http://" or "https://" and contains a valid network location.

2. Security Indicator Detection

The URL is checked against predefined rule-based indicators such as IP addresses, suspicious symbols, security-related keywords, unusual ports and long URLs.

3. Risk Scoring

Each detected indicator contributes a predefined number of points to the overall risk score.

4. Risk Classification

The total score is classified into Low, Medium or High risk.

5. Scan Storage

The scan result, URL, timestamp, score and detected indicators are stored in a local SQLite database.

---

Running the Project

1. Activate the virtual environment

On Windows:

venv\Scripts\activate

2. Install dependencies

pip install -r requirements.txt

3. Run the application

python app.py

4. Open the application

Open the local Flask address shown in the terminal, normally:

http://127.0.0.1:5000/

---

Important Limitation

PhishGuard is a rule-based URL analysis prototype.

A high risk score does not prove that a website is malicious, and a low score does not guarantee that a website is safe.

The results should be treated as security indicators that can help with further investigation and security awareness.

---

Purpose

PhishGuard was developed as a defensive cybersecurity project to demonstrate:

- URL security analysis
- Rule-based detection
- Risk scoring
- Web application development
- Backend and database integration
- Security awareness

---

Project Status

Working prototype

The application includes URL scanning, risk assessment, scan history, analytics, scan details, settings and report export functionality.