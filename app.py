import streamlit as st
import joblib
import re
import csv
import os
from datetime import datetime


model = joblib.load("models/phishing_detector.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")

def log_analysis(email_text, label, probability, threat_level, reasons, matched_words, links, domains, sender_info):
    log_file = "analysis_log.csv"
    file_exists = os.path.isfile(log_file)

    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "label",
                "confidence",
                "threat_level",
                "reasons",
                "matched_words",
                "links",
                "domains",
                "sender"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            label,
            f"{probability:.4f}",
            threat_level,
            "; ".join(reasons),
            ", ".join(matched_words),
            ", ".join(links),
            ", ".join(domains),
            sender_info if sender_info else "None"
        ])

def clean_text(text):
    return text.lower().strip()


def explain_prediction(text):
    text_lower = text.lower()
    reasons = []

    patterns = {
        "verify": "The email asks you to verify or confirm your account.",
        "confirm": "The email asks you to verify or confirm your account.",
        "suspend": "It mentions account suspension to create fear.",
        "suspended": "It mentions account suspension to create fear.",
        "click": "It encourages clicking a link, which may be malicious.",
        "link": "It encourages clicking a link, which may be malicious.",
        "urgent": "It uses urgency to pressure you.",
        "immediately": "It uses urgency to pressure you.",
        "password": "It references passwords or login details.",
        "login": "It references passwords or login details.",
        "update": "It mentions security updates, often used in phishing emails.",
        "security": "It mentions security updates, often used in phishing emails."
    }

    matched_words = []

    for word, reason in patterns.items():
        if re.search(rf"\b{word}\b", text_lower):
            matched_words.append(word)
            if reason not in reasons:
                reasons.append(reason)

    if not reasons:
        reasons.append("No strong phishing indicators detected.")

    return reasons, matched_words


def analyze_email(text):
    cleaned = clean_text(text)
    features = vectorizer.transform([cleaned])

    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0][1]
    label = "PHISHING" if prediction == 1 else "LEGITIMATE"

    reasons, matched_words = explain_prediction(text)

    return label, probability, reasons, matched_words


def get_threat_level(probability):
    if probability >= 0.8:
        return "High"
    elif probability >= 0.5:
        return "Medium"
    else:
        return "Low"


def extract_links(text):
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text)



def analyze_domain(domain):
    reasons = []

    # Suspicious TLDs
    suspicious_tlds = ["xyz", "top", "click", "info", "online", "live"]
    tld = domain.split(".")[-1]
    if tld in suspicious_tlds:
        reasons.append(f"Domain uses a suspicious TLD: .{tld}")

    # Hyphens or numbers in domain
    if "-" in domain or any(char.isdigit() for char in domain):
        reasons.append("Domain contains hyphens or numbers, common in phishing domains.")

    # Impersonation patterns
    impersonation_keywords = ["secure", "verify", "login", "update", "support"]
    if any(word in domain for word in impersonation_keywords):
        reasons.append("Domain contains impersonation keywords often used in phishing.")

    if not reasons:
        reasons.append("No suspicious domain indicators detected.")

    return reasons

def extract_domains(links):
    domains = []
    for link in links:
        try:
            domain = link.split("//")[1].split("/")[0]
            domains.append(domain)
        except:
            pass
    return domains

def analyze_sender(email_text):
    sender_info = None
    reasons = []

    for line in email_text.split("\n"):
        if line.lower().startswith("from:"):
            sender_info = line[5:].strip()
            break

    if not sender_info:
        return None, ["No sender information found."]

    # Free email providers used for business impersonation
    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    domain = sender_info.split("@")[-1].lower()

    if domain in free_providers:
        reasons.append("Sender uses a free email provider, unusual for business communication.")

    # Display name mismatch
    if "<" in sender_info and ">" in sender_info:
        display_name = sender_info.split("<")[0].strip()
        email_addr = sender_info.split("<")[1].replace(">", "").strip()
        if display_name.lower() not in email_addr.lower():
            reasons.append("Display name does not match email address, possible impersonation.")

    # Homoglyph detection (basic)
    suspicious_chars = ["о", "е", "і", "ѕ", "ӏ"]  # Cyrillic lookalikes
    if any(char in sender_info for char in suspicious_chars):
        reasons.append("Sender contains unusual characters that may indicate homoglyph spoofing.")

    if not reasons:
        reasons.append("No suspicious sender indicators detected.")

    return sender_info, reasons

def forensic_breakdown(email_text, matched_words, links, domain_results, sender_results):
    breakdown = {
        "Total suspicious words": len(matched_words),
        "Total links": len(links),
        "Total domains": len(domain_results),
        "Sender issues": len(sender_results),
        "Urgency detected": any(word in email_text.lower() for word in ["urgent", "immediately", "asap"]),
        "Credential language detected": any(word in email_text.lower() for word in ["password", "login", "account"]),
        "Financial language detected": any(word in email_text.lower() for word in ["invoice", "payment", "bank", "transfer"])
    }
    return breakdown

def generate_report(email_text, label, probability, threat_level, reasons, matched_words, links, domain_results, sender_info, sender_results, breakdown):
    report = []
    report.append("PHISHING ANALYSIS REPORT")
    report.append("=" * 40)
    report.append(f"Prediction: {label}")
    report.append(f"Confidence: {probability * 100:.2f}%")
    report.append(f"Threat Level: {threat_level}")
    report.append("\nReasons:")
    for r in reasons:
        report.append(f"- {r}")

    report.append("\nSuspicious Words:")
    report.append(", ".join(matched_words) if matched_words else "None")

    report.append("\nLinks Found:")
    for link in links:
        report.append(f"- {link}")

    report.append("\nDomain Analysis:")
    for domain, dr in domain_results.items():
        report.append(f"{domain}:")
        for reason in dr:
            report.append(f"- {reason}")

    report.append("\nSender Analysis:")
    report.append(f"Sender: {sender_info if sender_info else 'None'}")
    for reason in sender_results:
        report.append(f"- {reason}")

    report.append("\nForensic Breakdown:")
    for key, value in breakdown.items():
        report.append(f"{key}: {value}")

    report.append("\nFull Email Body:")
    report.append(email_text)

    return "\n".join(report)

# ---------------- UI ----------------

st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide"
)

st.markdown(
    """
    <h1 style='text-align: center; color: #2E86C1;'>🛡️ Phishing Email Detection Dashboard</h1>
    <p style='text-align: center; font-size: 18px;'>
        AI-powered SOC triage assistant for analysing suspicious emails.
    </p>
    """,
    unsafe_allow_html=True
)

st.markdown("---")

input_col, result_col = st.columns([1.2, 1])

with input_col:
    st.subheader("Email Input")
    email_text = st.text_area(
        "Paste the email content below:",
        height=300,
        placeholder="Enter the full email body here..."
    )

    analyze_button = st.button("Analyse Email", use_container_width=True)
with result_col:
    st.subheader("Analysis Summary")

    if analyze_button and email_text.strip():
        label, probability, reasons, matched_words = analyze_email(email_text)
        threat_level = get_threat_level(probability)
        links = extract_links(email_text)
        domains = extract_domains(links)

        # Domain analysis
        domain_results = {domain: analyze_domain(domain) for domain in domains}

        # Sender analysis
        sender_info, sender_results = analyze_sender(email_text)

        # Forensic breakdown
        breakdown = forensic_breakdown(email_text, matched_words, links, domain_results, sender_results)

        # Threat banner
        if threat_level == "High":
            banner_color = "#E74C3C"
        elif threat_level == "Medium":
            banner_color = "#F39C12"
        else:
            banner_color = "#27AE60"

        st.markdown(
            f"""
            <div style='padding: 15px; border-radius: 10px; background-color: {banner_color}; color: white;'>
                <h3 style='margin: 0;'>Threat Level: {threat_level}</h3>
                <p style='margin: 0;'>Confidence: {probability * 100:.2f}%</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # LOG ANALYSIS
        log_analysis(
            email_text, label, probability, threat_level,
            reasons, matched_words, links, domains, sender_info
        )

        st.markdown("### Prediction")
        st.write(f"Result: {label}")

        st.markdown("### Reasons for Classification")
        for r in reasons:
            st.write(f"- {r}")

        if matched_words:
            st.markdown("### Suspicious Words Detected")
            st.write(", ".join(sorted(set(matched_words))))

        if links:
            st.markdown("### Links Found")
            for link in links:
                st.write(f"- {link}")

        if domains:
            st.markdown("### Domain Analysis")
            for domain, dr in domain_results.items():
                st.write(f"**{domain}**")
                for reason in dr:
                    st.write(f"- {reason}")

        st.markdown("### Sender Analysis")
        if sender_info:
            st.write(f"Sender: {sender_info}")
        for reason in sender_results:
            st.write(f"- {reason}")

        st.markdown("### Forensic Breakdown")
        for key, value in breakdown.items():
            st.write(f"**{key}:** {value}")

        # FULL EMAIL BODY
        st.markdown("### Full Email Body")
        st.code(email_text, language="text")

        # GENERATE REPORT (NOW SAFE)
        report_text = generate_report(
            email_text, label, probability, threat_level,
            reasons, matched_words, links, domain_results,
            sender_info, sender_results, breakdown
        )

        # DOWNLOAD BUTTON (NOW SAFE)
        st.download_button(
            label="📄 Download Full Report",
            data=report_text,
            file_name="phishing_report.txt",
            mime="text/plain"
        )

    elif analyze_button:
        st.write("Please paste an email before analysing.")




