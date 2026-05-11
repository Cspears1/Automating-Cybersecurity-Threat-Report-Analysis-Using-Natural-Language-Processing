#!/usr/bin/env python3


import argparse
import math
import os
import re
from collections import Counter, defaultdict


TRAINING_DATA = [
    # 4phishing
    ("phishing", "spoofed login email redirects users to a fake secure login page and harvests credentials"),
    ("phishing", "credential theft campaign uses malicious email messages and fake password reset links"),
    ("phishing", "employees received suspicious email asking them to verify account credentials"),
    ("phishing", "fake login portal collects usernames passwords and session tokens"),
    ("phishing", "phishing campaign uses social engineering and malicious links to steal credentials"),
    ("phishing", "spear phishing email impersonates a trusted vendor and tricks employee into entering credentials"),
    ("phishing", "attackers registered a lookalike domain to host a convincing fake banking login page"),
    ("phishing", "mass phishing wave used invoice lure emails to redirect victims to credential harvesting sites"),
    ("phishing", "smishing campaign sent SMS messages with malicious links to fake parcel delivery pages"),
    ("phishing", "business email compromise attack spoofed CFO to redirect wire transfer payments"),
    ("phishing", "adversary cloned a corporate VPN portal and used typosquatting domain to collect passwords"),
    ("phishing", "multi-stage phishing kit bypassed multi-factor authentication via session cookie theft"),
    ("phishing", "threat actor sent targeted phishing with weaponized document to executive team"),
    ("phishing", "fake IT helpdesk email prompted users to reset passwords on attacker controlled site"),
    ("phishing", "whaling attack impersonated CEO email to authorize fraudulent financial transactions"),

    # 4 ransomware
    ("ransomware", "ransomware encrypted shared files and demanded payment for decryption keys"),
    ("ransomware", "malware locked systems deleted backups and displayed a ransom note"),
    ("ransomware", "attackers deployed ransomware across endpoints causing file encryption and downtime"),
    ("ransomware", "healthcare systems were encrypted after users opened a malicious invoice attachment"),
    ("ransomware", "ransomware operators threatened data leak if victims refused to pay ransom"),
    ("ransomware", "double extortion ransomware exfiltrated sensitive files before encrypting the environment"),
    ("ransomware", "ransomware spread laterally via SMB exploits and encrypted network shares"),
    ("ransomware", "backup systems were destroyed before ransomware payload was detonated"),
    ("ransomware", "critical infrastructure operator suffered ransomware attack halting operations for days"),
    ("ransomware", "ransomware gang published stolen files on leak site after victim declined to pay"),
    ("ransomware", "initial access broker sold credentials that were used to deploy ransomware weeks later"),
    ("ransomware", "ransomware variant used living-off-the-land techniques to evade endpoint detection"),
    ("ransomware", "attackers used RDP brute force to gain foothold before executing ransomware payload"),
    ("ransomware", "cloud storage buckets were also encrypted as part of the ransomware campaign"),
    ("ransomware", "ransomware note demanded cryptocurrency payment within 72 hours or threatened data destruction"),

    # 4 malware
    ("malware", "malicious payload contacted command and control server and downloaded additional malware"),
    ("malware", "trojan malware established persistence and executed suspicious process activity"),
    ("malware", "payload hash was linked to malware that exfiltrated browser data"),
    ("malware", "malware infection created registry keys and communicated with a remote domain"),
    ("malware", "backdoor malware allowed unauthorized remote access to the compromised host"),
    ("malware", "infostealer malware harvested saved passwords browser cookies and crypto wallet keys"),
    ("malware", "rootkit malware hid malicious processes from antivirus and security monitoring tools"),
    ("malware", "dropper delivered second stage payload from encrypted memory region to avoid detection"),
    ("malware", "keylogger malware captured keystrokes and periodically sent logs to attacker infrastructure"),
    ("malware", "malware used process injection to run malicious code inside legitimate system processes"),
    ("malware", "wiper malware destroyed master boot record rendering affected machines unbootable"),
    ("malware", "fileless malware lived in memory and used PowerShell to execute commands without disk artifacts"),
    ("malware", "remote access trojan allowed attackers to take screenshots and control infected systems"),
    ("malware", "botnet malware enrolled compromised hosts into DDoS attack infrastructure"),
    ("malware", "banking trojan intercepted online transactions and redirected funds to attacker accounts"),

    # 4 vulnerability
    ("vulnerability", "attackers exploited a CVE vulnerability to gain unauthorized access"),
    ("vulnerability", "zero day vulnerability allowed remote code execution against exposed servers"),
    ("vulnerability", "unpatched software flaw was exploited during the intrusion"),
    ("vulnerability", "security advisory reported active exploitation of a critical CVE"),
    ("vulnerability", "exploit chain abused vulnerable service and bypassed authentication"),
    ("vulnerability", "proof of concept exploit for critical CVE was released and exploited within hours"),
    ("vulnerability", "internet facing VPN appliance was compromised via authentication bypass vulnerability"),
    ("vulnerability", "attackers used SQL injection vulnerability to dump database of user credentials"),
    ("vulnerability", "remote code execution flaw in web server was used to deploy webshell"),
    ("vulnerability", "privilege escalation vulnerability allowed attacker to gain administrator access"),
    ("vulnerability", "supply chain attack introduced malicious code through vulnerable third party library"),
    ("vulnerability", "SSRF vulnerability exposed cloud metadata endpoint and leaked service credentials"),
    ("vulnerability", "directory traversal flaw in file upload handler allowed attacker to overwrite system files"),
    ("vulnerability", "buffer overflow in network service enabled unauthenticated remote code execution"),
    ("vulnerability", "patch management failure left hundreds of endpoints exposed to known critical CVE"),

    # 4 apt
    ("apt", "advanced persistent threat actor used stealthy tactics techniques and procedures"),
    ("apt", "nation state group performed reconnaissance lateral movement and data exfiltration"),
    ("apt", "threat actor campaign targeted government networks using custom tools"),
    ("apt", "APT operators maintained persistence and moved laterally across the network"),
    ("apt", "long term intrusion involved command and control and credential dumping"),
    ("apt", "nation state sponsored group used living off the land binaries to blend in with normal traffic"),
    ("apt", "espionage focused threat actor stole classified documents over a period of several months"),
    ("apt", "APT group compromised managed service provider to pivot into downstream customer networks"),
    ("apt", "highly sophisticated threat actor used custom implants and encrypted covert channels"),
    ("apt", "state sponsored group targeted defense contractors and research institutions"),
    ("apt", "APT actor used watering hole attack to compromise industry specific news site and infect visitors"),
    ("apt", "intrusion set maintained access for over a year before exfiltrating intellectual property"),
    ("apt", "threat group rotated command and control infrastructure frequently to evade detection and blocking"),
    ("apt", "APT campaign used legitimate cloud services as command and control channels to blend in"),
    ("apt", "nation state actor conducted destructive wiper attack against critical national infrastructure"),
]


SEVERITY_TRAINING_DATA = [
    # High 
    ("high", "ransomware encrypted all servers destroyed backups demanding bitcoin ransom ip_address_indicator file_hash_indicator"),
    ("high", "critical zero day remote code execution exploited in the wild against unpatched systems cve_identifier ip_address_indicator"),
    ("high", "nation state actor exfiltrated classified data and deployed destructive wiper malware domain_indicator"),
    ("high", "ransomware operators published stolen sensitive data after victim refused to pay file_hash_indicator"),
    ("high", "healthcare network paralyzed by ransomware affecting patient care and critical systems ip_address_indicator cve_identifier file_hash_indicator"),
    ("high", "attacker achieved domain admin access and deployed ransomware across the entire network"),
    ("high", "supply chain compromise injected backdoor into widely used software affecting thousands cve_identifier domain_indicator"),
    ("high", "critical infrastructure operator suffered complete operational shutdown from cyberattack ip_address_indicator"),
    ("high", "APT exfiltrated years of intellectual property before detection over eighteen months domain_indicator"),
    ("high", "wiper malware destroyed master boot record on hundreds of hosts causing mass outage file_hash_indicator"),
    ("high", "active intrusion used suspicious domain cve identifier file hash and external ip address to compromise systems domain_indicator cve_identifier file_hash_indicator ip_address_indicator"),

    # Medium 
    ("medium", "phishing campaign harvested employee credentials and led to unauthorized access ip_address_indicator domain_indicator"),
    ("medium", "malware infection established command and control and exfiltrated browser saved passwords domain_indicator"),
    ("medium", "unpatched CVE exploited to gain initial foothold on an internet facing web server cve_identifier"),
    ("medium", "trojan installed on workstation and communicated with suspicious external domain domain_indicator"),
    ("medium", "unauthorized access detected on internal network with lateral movement observed"),
    ("medium", "infostealer malware collected credentials from several employee workstations file_hash_indicator"),
    ("medium", "spear phishing email with malicious attachment opened by finance department employee"),
    ("medium", "vulnerability exploited in VPN appliance allowing attacker access to internal segment cve_identifier"),
    ("medium", "backdoor malware discovered on developer workstation with signs of data staging domain_indicator"),
    ("medium", "credential stuffing attack caused multiple account takeovers on customer portal"),

    # Low 
    ("low", "security advisory issued for vulnerability with no evidence of active exploitation"),
    ("low", "suspicious email quarantined by mail gateway with no user interaction recorded"),
    ("low", "routine port scan detected from external IP address no intrusion observed ip_address_indicator"),
    ("low", "phishing email blocked before delivery no credentials entered by employees"),
    ("low", "monitoring alert triggered on outbound connection that was confirmed as false positive"),
    ("low", "patch released for medium severity vulnerability in third party component"),
    ("low", "low confidence malware alert on endpoint cleared after investigation found no infection"),
    ("low", "security warning about weak password policy issued with no current active threat"),
    ("low", "informational advisory about new threat actor tactics with no targeted activity detected"),
    ("low", "vendor notified of minor information disclosure vulnerability in their web application"),
]

STOP_WORDS = {
    "a", "an", "the", "and", "or", "but", "is", "are", "was", "were", "to", "of", "in",
    "on", "for", "with", "by", "from", "as", "at", "this", "that", "it", "be", "been",
    "has", "have", "had", "into", "after", "during", "about", "should", "users", "user",
    "its", "their", "they", "also", "after", "before", "than", "when", "which", "while",
}

CONFIDENCE_THRESHOLD = 45.0   



def tokenize(text):
    tokens = re.findall(r"[a-zA-Z0-9\-]+", text.lower())
    return [t for t in tokens if t not in STOP_WORDS and len(t) > 1]



def compute_tfidf(labeled_examples):
    """
    Returns a dict: label -> {token: tfidf_weight}
    Documents within the same class are treated as one big document per class
    for the TF part; IDF is computed across all per-class documents.
    """

    class_tokens = defaultdict(list)
    for label, text in labeled_examples:
        class_tokens[label].extend(tokenize(text))

    all_labels = list(class_tokens.keys())
    num_classes = len(all_labels)


    class_tf = {}
    for label, tokens in class_tokens.items():
        count = Counter(tokens)
        total = sum(count.values())
        class_tf[label] = {token: freq / total for token, freq in count.items()}


    doc_freq = Counter()
    for label, tokens in class_tokens.items():
        for token in set(tokens):
            doc_freq[token] += 1

    idf = {
        token: math.log((num_classes + 1) / (freq + 1)) + 1
        for token, freq in doc_freq.items()
    }

   
    tfidf = {}
    for label in all_labels:
        tfidf[label] = {
            token: tf_val * idf.get(token, 1.0)
            for token, tf_val in class_tf[label].items()
        }

    return tfidf

class TFIDFNaiveBayesClassifier:
    """
    Naive Bayes classifier that uses TF-IDF weights instead of raw counts.
    During prediction, each token's contribution to a class log-probability
    is scaled by that token's TF-IDF weight in the training corpus.
    """

    def __init__(self):
        self.class_prior = {}
        self.tfidf_weights = {}      
        self.vocabulary = set()

    def train(self, labeled_examples):
        total = len(labeled_examples)
        label_counts = Counter(label for label, _ in labeled_examples)
        self.class_prior = {
            label: count / total for label, count in label_counts.items()
        }
        self.tfidf_weights = compute_tfidf(labeled_examples)
        for weights in self.tfidf_weights.values():
            self.vocabulary.update(weights.keys())

    def predict(self, text):
        tokens = tokenize(text)
        scores = {}

        for label in self.class_prior:
            log_prob = math.log(self.class_prior[label])
            weights = self.tfidf_weights[label]
            weight_sum = sum(weights.values())

            for token in tokens:
    
                w = weights.get(token, 0.0)
            
                token_prob = (w + 1e-4) / (weight_sum + len(self.vocabulary) * 1e-4)
                log_prob += math.log(token_prob)

            scores[label] = log_prob

        best_label = max(scores, key=scores.get)
        max_score = max(scores.values())
        exp_scores = {label: math.exp(score - max_score) for label, score in scores.items()}
        total_exp = sum(exp_scores.values())
        confidence = {
            label: round((v / total_exp) * 100, 2) for label, v in exp_scores.items()
        }
        return best_label, confidence



def extract_iocs(text):
    patterns = {
        "IP Addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "Domains":      r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "CVE IDs":      r"\bCVE-\d{4}-\d{4,7}\b",
        "MD5 Hashes":   r"\b[a-fA-F0-9]{32}\b",
        "SHA1 Hashes":  r"\b[a-fA-F0-9]{40}\b",
        "SHA256 Hashes":r"\b[a-fA-F0-9]{64}\b",
        "Emails":       r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    }
    return {
        name: sorted(set(re.findall(pattern, text, flags=re.IGNORECASE)))
        for name, pattern in patterns.items()
    }



def estimate_severity_learned(text, iocs, severity_classifier):
    """
    Uses the trained severity classifier to predict High / Medium / Low.
    IOC counts are appended as synthetic tokens to give the classifier
    additional signal from the structured IOC data.
    """

    ioc_tokens = []
    if len(iocs["IP Addresses"]) > 0:
        ioc_tokens.append("ip_address_indicator")
    if len(iocs["Domains"]) > 0:
        ioc_tokens.append("domain_indicator")
    if len(iocs["CVE IDs"]) > 0:
        ioc_tokens += ["cve_identifier"] * len(iocs["CVE IDs"])
    if len(iocs["MD5 Hashes"]) + len(iocs["SHA1 Hashes"]) + len(iocs["SHA256 Hashes"]) > 0:
        ioc_tokens.append("file_hash_indicator")

    augmented_text = text + " " + " ".join(ioc_tokens)
    predicted_severity, sev_confidence = severity_classifier.predict(augmented_text)
    top_confidence = sev_confidence[predicted_severity]
    return predicted_severity.capitalize(), round(top_confidence, 2), sev_confidence



def summarize_report(predicted_label, severity, iocs, confidence, low_confidence):
    findings = []
    if iocs["Domains"]:
        findings.append("domain(s): " + ", ".join(iocs["Domains"]))
    if iocs["IP Addresses"]:
        findings.append("IP address(es): " + ", ".join(iocs["IP Addresses"]))
    if iocs["CVE IDs"]:
        findings.append("CVE(s): " + ", ".join(iocs["CVE IDs"]))
    if iocs["MD5 Hashes"] or iocs["SHA1 Hashes"] or iocs["SHA256 Hashes"]:
        findings.append("file hash indicator(s)")
    finding_text = "; ".join(findings) if findings else "no clear IOCs found"

    classification_note = (
        f"NOTE: Classification confidence is LOW ({confidence:.1f}%). "
        "Manual analyst review is strongly recommended. "
        if low_confidence
        else ""
    )

    return (
        f"{classification_note}"
        f"The report was classified as {predicted_label.upper()} with {severity.upper()} severity. "
        f"The system identified {finding_text}. Recommended action: review extracted indicators, "
        f"block suspicious network indicators, and escalate for analyst review."
    )



# Main


def apply_hybrid_severity_safety_rule(text, iocs, severity):

    text_lower = text.lower()
    serious_keywords = [
        "ransomware", "encrypted", "exfiltration", "wiper", "critical",
        "domain admin", "healthcare", "patient care", "operational shutdown",
        "remote code execution", "zero day", "destroyed backups"
    ]

    ioc_count = (
        len(iocs["IP Addresses"]) +
        len(iocs["Domains"]) +
        len(iocs["CVE IDs"]) +
        len(iocs["MD5 Hashes"]) +
        len(iocs["SHA1 Hashes"]) +
        len(iocs["SHA256 Hashes"])
    )

    if severity.lower() in ["low", "medium"] and ioc_count >= 2 and any(word in text_lower for word in serious_keywords):
        return "high", True

    if severity.lower() == "low" and ioc_count >= 3:
        return "medium", True

    return severity, False


def main():
    parser = argparse.ArgumentParser(description="AI/ML NLP Threat Report Analyzer (Enhanced)")
    parser.add_argument("report_file", help="Path to threat report text file")
    args = parser.parse_args()

    if not os.path.exists(args.report_file):
        print(f"Error: File not found: {args.report_file}")
        return

    with open(args.report_file, "r", encoding="utf-8") as fh:
        report_text = fh.read().strip()


    threat_classifier = TFIDFNaiveBayesClassifier()
    threat_classifier.train(TRAINING_DATA)

    severity_classifier = TFIDFNaiveBayesClassifier()
    severity_classifier.train(SEVERITY_TRAINING_DATA)


    predicted_label, confidence = threat_classifier.predict(report_text)
    iocs = extract_iocs(report_text)
    severity, sev_top_conf, sev_confidence = estimate_severity_learned(
        report_text, iocs, severity_classifier
    )
    severity, severity_adjusted = apply_hybrid_severity_safety_rule(report_text, iocs, severity)

    top_confidence = confidence[predicted_label]
    low_confidence = top_confidence < CONFIDENCE_THRESHOLD
    summary = summarize_report(predicted_label, severity, iocs, top_confidence, low_confidence)
    if severity_adjusted:
        summary = (
            "Manual review note: the learned severity model was adjusted by the hybrid safety rule "
            "because the report contained multiple IOCs and serious impact language. " + summary
        )

    # Out
    print("\n=== AI / Machine Learning NLP Threat Report Analyzer ===\n")
    print("INPUT REPORT:")
    print(report_text)

    print("\n--- MACHINE LEARNING CLASSIFICATION  (TF-IDF Naive Bayes) ---")
    print(f"Predicted Threat Category : {predicted_label.upper()}")
    print(f"Top Confidence            : {top_confidence}%")
    if low_confidence:
        print(f"  ⚠  CONFIDENCE BELOW THRESHOLD ({CONFIDENCE_THRESHOLD}%) — flagged for manual review")
    print("\nAll Classification Confidence Scores:")
    for label, score in sorted(confidence.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(score / 5)
        print(f"  {label:<15} {score:>6.2f}%  {bar}")

    print("\n--- SEVERITY ESTIMATION  (Learned Classifier) ---")
    print(f"Predicted Severity   : {severity.upper()}")
    print(f"Severity Confidence  : {sev_top_conf}%")
    if severity_adjusted:
        print("Severity Adjustment  : Applied hybrid safety rule for serious incident indicators")
    print("\nAll Severity Confidence Scores:")
    for label, score in sorted(sev_confidence.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(score / 5)
        print(f"  {label:<10} {score:>6.2f}%  {bar}")

    print("\n--- EXTRACTED INDICATORS OF COMPROMISE ---")
    for ioc_type, values in iocs.items():
        if values:
            print(f"{ioc_type}:")
            for value in values:
                print(f"  - {value}")
        else:
            print(f"{ioc_type}: None found")

    print("\n--- ANALYST SUMMARY ---")
    print(summary)
    print("\nDemo complete.\n")


if __name__ == "__main__":
    main()
