import { useState } from "react";

import {
  ShieldCheck,
  ShieldAlert,
  Search,
  LayoutDashboard,
  Link as LinkIcon,
  Mail,
  Globe,
  AlertTriangle,
  ArrowRight,
  LockKeyhole,
  Activity,
  CheckCircle2,
  XCircle,
  LoaderCircle,
  Menu,
  X,
} from "lucide-react";

import "./App.css";
import PasswordChecker from "./PasswordChecker";

// Backend API configuration
const API_URL = "/api";

// Send requests to the Flask backend
async function requestAPI(endpoint, data) {
  let response;

  try {
    response = await fetch(`${API_URL}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });
  } catch {
    throw new Error(
      "Cannot connect to the backend. Check that your backend is running and your API URL is correct."
    );
  }

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error("The backend returned an invalid response.");
  }

  if (!response.ok || result.success === false) {
    throw new Error(
      result.error || result.message || "The analysis request failed."
    );
  }

  return result;
}

// Format risk levels consistently
function getRiskLevel(result) {
  return String(
    result?.risk_level ||
      result?.riskLevel ||
      result?.risk ||
      "Unknown"
  );
}

// Get numerical risk score
function getRiskScore(result) {
  const score = Number(
    result?.risk_score ??
      result?.score ??
      result?.security_score ??
      0
  );

  return Number.isFinite(score)
    ? Math.min(100, Math.max(0, score))
    : 0;
}

// Get findings from the backend
function getFindings(result) {
  if (Array.isArray(result?.findings)) {
    return result.findings;
  }

  if (Array.isArray(result?.results)) {
    return result.results;
  }

  return [];
}

// Format finding severity
function getSeverity(finding) {
  return String(
    finding?.severity ||
      finding?.status ||
      finding?.risk ||
      "info"
  ).toLowerCase();
}

// Convert severity to an existing CSS status class
function getStatusClass(severity) {
  const value = String(severity).toLowerCase();

  if (
    ["safe", "secure", "pass", "passed", "success", "good", "low"].includes(
      value
    )
  ) {
    return "low";
  }

  if (["medium", "moderate", "warning"].includes(value)) {
    return "medium";
  }

  if (
    ["high", "critical", "danger", "error", "failed"].includes(value)
  ) {
    return "high";
  }

  return "unknown";
}

// Display finding status
function FindingStatus({ finding }) {
  const severity = getSeverity(finding);
  const statusClass = getStatusClass(severity);

  return (
    <span className={`status-badge status-${statusClass}`}>
      {severity}
    </span>
  );
}

// DNS Report Component
function DNSReport({ dnsData }) {
  if (!dnsData) {
    return (
      <section className="dns-report">
        <div className="dns-report-header">
          <div>
            <span className="page-eyebrow">DOMAIN INTELLIGENCE</span>
            <h2>DNS Report</h2>
            <p>
              DNS information was not included in the backend response.
            </p>
          </div>

          <div className="dns-report-icon">
            <Globe size={24} />
          </div>
        </div>
      </section>
    );
  }

  const records = [
    {
      key: "ip_addresses",
      label: "IPv4 Addresses",
      type: "A",
    },
    {
      key: "ipv6_addresses",
      label: "IPv6 Addresses",
      type: "AAAA",
    },
    {
      key: "mx_records",
      label: "Mail Exchange Records",
      type: "MX",
    },
    {
      key: "nameservers",
      label: "Nameservers",
      type: "NS",
    },
  ];

  function getRecordValues(key) {
    const values = dnsData[key];

    if (Array.isArray(values)) {
      return values;
    }

    if (typeof values === "string" && values.trim()) {
      return [values];
    }

    return [];
  }

  return (
    <section className="dns-report">
      <div className="dns-report-header">
        <div>
          <span className="page-eyebrow">DOMAIN INTELLIGENCE</span>
          <h2>DNS Report</h2>
          <p>Domain infrastructure information</p>
        </div>

        <div className="dns-report-icon">
          <Globe size={24} />
        </div>
      </div>

      <div className="dns-hostname">
        <span>Hostname</span>
        <strong>{dnsData.hostname || "Unknown"}</strong>
      </div>

      <div className="dns-record-grid">
        {records.map((record) => {
          const values = getRecordValues(record.key);

          return (
            <div className="dns-record-card" key={record.key}>
              <div className="dns-record-card-heading">
                <span className="dns-record-type">{record.type}</span>
                <h3>{record.label}</h3>
              </div>

              {values.length > 0 ? (
                <ul className="dns-record-list">
                  {values.map((value, index) => (
                    <li key={`${record.key}-${index}`}>
                      <code>
                        {typeof value === "object"
                          ? JSON.stringify(value)
                          : String(value)}
                      </code>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="dns-empty-value">
                  {dnsData.available === false
                    ? "Lookup unavailable for this target."
                    : "None found"}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {Array.isArray(dnsData.findings) && (
        <div className="dns-findings">
          <h3>DNS Findings</h3>

          {dnsData.findings.length > 0 ? (
            dnsData.findings.map((finding, index) => (
              <div
                className="dns-finding-item"
                key={`${finding.name || "finding"}-${index}`}
              >
                <AlertTriangle size={17} />

                <div>
                  <strong>{finding.name || "DNS Finding"}</strong>

                  <p>
                    {finding.evidence ||
                      finding.message ||
                      finding.description ||
                      "No additional details are available."}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <p>No DNS findings were returned.</p>
          )}
        </div>
      )}

      <p className="dns-report-note">
        DNS records provide technical information about a domain. Missing
        records do not automatically mean that a website is malicious, and
        DNS records alone cannot establish trustworthiness.
      </p>
    </section>
  );
}

// Threat Intelligence Component
function ThreatIntelligence({ data }) {
  if (!data) {
    return null;
  }

  const providers =
    typeof data === "object" && data !== null
      ? Object.entries(data)
      : [];

  function formatLabel(value) {
    return value
      .replace(/_/g, " ")
      .replace(/\b\w/g, (character) => character.toUpperCase());
  }

  function formatValue(value) {
    if (value === null || value === undefined || value === "") {
      return "Not available";
    }

    if (typeof value === "boolean") {
      return value ? "Yes" : "No";
    }

    if (typeof value === "object") {
      return JSON.stringify(value, null, 2);
    }

    return String(value);
  }

  return (
    <section className="dns-report">
      <div className="dns-report-header">
        <div>
          <span className="page-eyebrow">THREAT INTELLIGENCE</span>
          <h2>Threat Intelligence Results</h2>
          <p>External threat indicator information</p>
        </div>

        <div className="dns-report-icon">
          <ShieldAlert size={24} />
        </div>
      </div>

      {providers.length > 0 ? (
        <div className="dns-record-grid">
          {providers.map(([key, value]) => (
            <div className="dns-record-card" key={key}>
              <div className="dns-record-card-heading">
                <span className="dns-record-type">TI</span>
                <h3>{formatLabel(key)}</h3>
              </div>

              {typeof value === "object" &&
              value !== null &&
              !Array.isArray(value) ? (
                <ul className="dns-record-list">
                  {Object.entries(value).map(
                    ([nestedKey, nestedValue]) => (
                      <li key={nestedKey}>
                        <strong>{formatLabel(nestedKey)}:</strong>{" "}
                        <code>{formatValue(nestedValue)}</code>
                      </li>
                    )
                  )}
                </ul>
              ) : (
                <p>{formatValue(value)}</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        <p>No threat intelligence information was returned.</p>
      )}

      <p className="dns-report-note">
        No match in a threat intelligence database does not guarantee that
        a URL is safe.
      </p>
    </section>
  );
}

// Email Reputation Report Component
function EmailReputationReport({ data }) {
  if (!data) {
    return (
      <section className="dns-report">
        <div className="dns-report-header">
          <div>
            <span className="page-eyebrow">EMAIL INTELLIGENCE</span>
            <h2>Email Reputation Report</h2>
            <p>
              Reputation information was not returned by the backend.
            </p>
          </div>

          <div className="dns-report-icon">
            <ShieldAlert size={24} />
          </div>
        </div>
      </section>
    );
  }

  const checks = [
    {
      key: "valid_format",
      title: "Email Format Validity",
      positiveWhenTrue: true,
      description: "Whether the service considers the email format valid.",
    },
    {
      key: "is_disposable",
      title: "Disposable Email Detection",
      positiveWhenTrue: false,
      description: "Whether the address uses a disposable email provider.",
    },
    {
      key: "is_known_spammer",
      title: "Known Spammer Status",
      positiveWhenTrue: false,
      description: "Whether the service flags the address as a known spammer.",
    },
    {
      key: "community_blacklisted",
      title: "Community Blacklist Status",
      positiveWhenTrue: false,
      description: "Whether the service reports a community blacklist match.",
    },
    {
      key: "safe_domain",
      title: "Domain Safety",
      positiveWhenTrue: true,
      description: "The domain safety indicator returned by the service.",
    },
    {
      key: "is_role_address",
      title: "Role-Based Address",
      positiveWhenTrue: false,
      description: "Whether the address may represent a shared mailbox.",
    },
  ];

  function getStatus(value, positiveWhenTrue) {
    if (value === null || value === undefined || value === "") {
      return {
        label: "Unknown",
        className: "unknown",
      };
    }

    if (typeof value === "boolean") {
      const positive = value === positiveWhenTrue;

      return {
        label: value
          ? positiveWhenTrue
            ? "Valid / Yes"
            : "Detected"
          : positiveWhenTrue
            ? "Invalid / No"
            : "Not Detected",
        className: positive ? "low" : "high",
      };
    }

    // Preserve strings returned by the reputation provider.
    // Do not guess whether an unfamiliar value means safe or unsafe.
    return {
      label: String(value),
      className: "unknown",
    };
  }

  const reportCount = data.blacklist_reports;
  const hasReportCount =
    reportCount !== null &&
    reportCount !== undefined &&
    reportCount !== "";

  return (
    <section className="dns-report email-reputation-report">
      <div className="dns-report-header">
        <div>
          <span className="page-eyebrow">EMAIL INTELLIGENCE</span>
          <h2>Email Reputation Report</h2>
          <p>
            Reputation indicators returned by{" "}
            {data.provider || "the external reputation service"}.
          </p>
        </div>

        <div className="dns-report-icon">
          <ShieldCheck size={24} />
        </div>
      </div>

      <div className="dns-record-grid">
        {checks.map((check) => {
          const status = getStatus(
            data[check.key],
            check.positiveWhenTrue
          );

          return (
            <div className="dns-record-card" key={check.key}>
              <div className="dns-record-card-heading">
                <span className="dns-record-type">EMAIL</span>
                <h3>{check.title}</h3>
              </div>

              <span className={`status-badge status-${status.className}`}>
                {status.label}
              </span>

              <p>{check.description}</p>
            </div>
          );
        })}
      </div>

      <div className="dns-hostname">
        <span>Email Domain</span>
        <strong>{data.domain || "Unknown"}</strong>
      </div>
      
<div className="dns-hostname">
  <span>Detection Source</span>
  <strong>
    {data.detection_source === "safe_domain"
      ? "Safe Domain Check"
      : data.detection_source || "Not available"}
  </strong>


      </div>

      <div className="dns-hostname">
        <span>Blacklist Reports</span>
        <strong>
          {hasReportCount ? String(reportCount) : "Not available"}
        </strong>
      </div>

      <p className="dns-report-note">
        These results depend on the information returned by the reputation
        service. Unknown results do not mean safe. A clean reputation result
        cannot guarantee trustworthiness, and a blacklist match alone does
        not prove malicious activity.
      </p>
    </section>
  );
}

// Analysis Results Component
function AnalysisResult({ result, type }) {
  if (!result) {
    return null;
  }

  const score = getRiskScore(result);
  const riskLevel = getRiskLevel(result);
  const normalizedRisk = getStatusClass(riskLevel);
  const findings = getFindings(result);

  const target =
    result.url ||
    result.email ||
    result.email_address ||
    result.target ||
    result.hostname ||
    "Analysis target";

  const dnsData =
    result.dns_intelligence ||
    result.dns_report ||
    result.dns ||
    null;

  const threatData =
    result.threat_intelligence ||
    result.threat_intel ||
    null;

  return (
    <div className="result-panel">
      <div className="section-heading">
        <div>
          <span className="page-eyebrow">INVESTIGATION COMPLETE</span>
          <h2>Analysis Results</h2>
        </div>

        <div className="score-icon">
          {normalizedRisk === "high" ? (
            <ShieldAlert size={25} />
          ) : (
            <ShieldCheck size={25} />
          )}
        </div>
      </div>

      <div className="analyzed-target">
        <span>Analyzed Target</span>
        <strong>{target}</strong>

        {result.investigation_id !== undefined && (
          <p>Investigation ID: #{result.investigation_id}</p>
        )}
      </div>

      <div className="result-score-card">
        <div className="score-label">
          <div>
            <span>Threat Assessment</span>
            <h3>{riskLevel} Risk</h3>
          </div>

          <span className={`status-badge status-${normalizedRisk}`}>
            {riskLevel}
          </span>
        </div>

        <div className="score-icon">
          {normalizedRisk === "high" ? (
            <ShieldAlert size={24} />
          ) : (
            <ShieldCheck size={24} />
          )}
        </div>

        <div className="score-progress">
          <div
            className="score-progress-fill"
            style={{ width: `${score}%` }}
          />
        </div>

        <p>
          Risk score: <strong>{score}/100</strong>
        </p>

        <p>
          {result.message ||
            result.summary ||
            "Review the findings below to understand the indicators identified during this investigation."}
        </p>

        <div className="result-type">
          <Activity size={17} />
          <span>
            {findings.length} finding
            {findings.length === 1 ? "" : "s"} identified
          </span>
        </div>
      </div>

      <div className="findings-section">
        <div className="section-heading">
          <div>
            <span className="page-eyebrow">INVESTIGATION DETAILS</span>
            <h3>Analysis Findings</h3>
          </div>
        </div>

        {findings.length > 0 ? (
          <div className="findings-list">
            {findings.map((finding, index) => {
              const severity = getSeverity(finding);

              const isPositive = [
                "low",
                "safe",
                "secure",
                "pass",
                "passed",
                "success",
                "good",
                "info",
                "informational",
              ].includes(severity);

              return (
                <div
                  className="finding-card"
                  key={
                    finding.id ||
                    `${finding.name || finding.title || "finding"}-${index}`
                  }
                >
                  <div className="finding-icon">
                    {isPositive ? (
                      <CheckCircle2 size={20} />
                    ) : (
                      <AlertTriangle size={20} />
                    )}
                  </div>

                  <div className="finding-content">
                    <div className="finding-title-row">
                      <h4>
                        {finding.name ||
                          finding.title ||
                          finding.check ||
                          `Finding ${index + 1}`}
                      </h4>

                      <FindingStatus finding={finding} />
                    </div>

                    <p>
                      {finding.evidence ||
                        finding.description ||
                        finding.message ||
                        finding.details ||
                        "No additional details were returned by the backend."}
                    </p>

                    {finding.points !== undefined && (
                      <p>Risk points: {finding.points}</p>
                    )}

                    {finding.recommendation && (
                      <div>
                        <strong>Recommendation</strong>
                        <p>{finding.recommendation}</p>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="empty-result">
            <CheckCircle2 size={22} />
            <p>No findings were returned by the analyzer.</p>
          </div>
        )}
      </div>

      {type === "url" && (
        <>
          <DNSReport dnsData={dnsData} />

          {threatData && <ThreatIntelligence data={threatData} />}
        </>
      )}

      {type === "email-address" && (
        <>
          <EmailReputationReport
            data={result.reputation_intelligence}
          />

          {dnsData && <DNSReport dnsData={dnsData} />}

          {threatData && <ThreatIntelligence data={threatData} />}
        </>
      )}

      <div className="result-disclaimer">
        <ShieldCheck size={19} />

        <p>
          <strong>Important:</strong>{" "}
          {result.disclaimer ||
            "This analysis provides indicators for investigation. It cannot guarantee that a URL or email is safe or malicious. Verify suspicious findings before taking action."}
        </p>
      </div>
    </div>
  );
}

// Dashboard Page
function DashboardPage({ setPage }) {
  const features = [
    {
      title: "URL Analysis",
      description:
        "Investigate URLs for suspicious indicators and domain information.",
      icon: LinkIcon,
      page: "url",
    },
    {
      title: "Email Analysis",
      description:
        "Examine email addresses and message content for phishing indicators.",
      icon: Mail,
      page: "email",
    },
    {
      title: "Password Checker",
      description:
        "Evaluate password strength and identify common weaknesses.",
      icon: LockKeyhole,
      page: "password",
    },
  ];

  return (
    <div className="dashboard-page">
      <section className="welcome-banner">
        <div className="welcome-content">
          <span className="welcome-label">PHISHGUARD PRO</span>

          <h1>
            Investigate threats.
            <br />
            <span>Protect digital identities.</span>
          </h1>

          <p>
            Your cybersecurity investigation dashboard for identifying
            suspicious URLs, analyzing phishing emails, and checking
            password strength.
          </p>

          <button
            className="primary-button"
            onClick={() => setPage("url")}
          >
            Start Investigation
            <ArrowRight size={18} />
          </button>
        </div>

        <div className="welcome-icon">
          <ShieldCheck size={100} strokeWidth={1.2} />
        </div>
      </section>

      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <span className="page-eyebrow">SECURITY TOOLS</span>
            <h2>Investigation Center</h2>
          </div>
        </div>

        <div className="feature-grid">
          {features.map((feature) => {
            const Icon = feature.icon;

            return (
              <button
                className="feature-card"
                key={feature.page}
                onClick={() => setPage(feature.page)}
              >
                <div className="feature-icon">
                  <Icon size={24} />
                </div>

                <h3>{feature.title}</h3>
                <p>{feature.description}</p>

                <span className="feature-action">
                  Open Tool
                  <ArrowRight size={16} />
                </span>
              </button>
            );
          })}
        </div>
      </section>

      <section className="privacy-notice">
        <div>
          <ShieldAlert size={22} />
        </div>

        <div>
          <h3>Investigate Before You Trust</h3>
          <p>
            Never enter passwords or sensitive information on suspicious
            websites. Use investigation tools as one part of your security
            checks.
          </p>
        </div>
      </section>
    </div>
  );
}

// URL Analysis Page
function URLAnalysisPage() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleAnalyze(event) {
    event.preventDefault();

    setError("");
    setResult(null);

    const cleanedURL = url.trim();

    if (!cleanedURL) {
      setError("Please enter a URL to analyze.");
      return;
    }

    setLoading(true);

    try {
      const data = await requestAPI("/analyze-url", {
        url: cleanedURL,
      });

      console.log("URL analysis response:", data);
      console.log("DNS intelligence:", data.dns_intelligence);
      console.log("Threat intelligence:", data.threat_intelligence);

      setResult(data);
    } catch (err) {
      setError(err.message || "The URL analysis request failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="analysis-page">
      <div className="page-header">
        <span className="page-eyebrow">INVESTIGATION TOOL</span>
        <h1>URL Analysis</h1>

        <p>
          Investigate a URL and review its security indicators, threat
          information, and DNS records.
        </p>
      </div>

      <div className="analysis-layout">
        <section className="analysis-form-panel">
          <div className="form-panel-heading">
            <div className="form-panel-icon">
              <LinkIcon size={23} />
            </div>

            <div>
              <h2>Investigate a URL</h2>
              <p>Enter the full URL you want to examine.</p>
            </div>
          </div>

          <form onSubmit={handleAnalyze}>
            <label htmlFor="url-input">Target URL</label>

            <div className="input-with-icon">
              <LinkIcon size={19} />

              <input
                id="url-input"
                type="text"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com"
                autoComplete="off"
              />
            </div>

            <button
              type="submit"
              className="primary-button analyze-button"
              disabled={loading}
            >
              {loading ? (
                <>
                  <LoaderCircle size={18} className="spin-icon" />
                  Analyzing URL...
                </>
              ) : (
                <>
                  <Search size={18} />
                  Analyze URL
                </>
              )}
            </button>
          </form>

          {error && (
            <div className="error-message">
              <XCircle size={19} />
              <p>{error}</p>
            </div>
          )}

          <p className="form-safety-note">
            Only analyze URLs you are authorized to investigate. A security
            analysis does not guarantee a website is safe.
          </p>
        </section>

        <div>
          {result ? (
            <AnalysisResult result={result} type="url" />
          ) : (
            <section className="result-panel empty-result">
              <Search size={28} />
              <h3>Analysis Results</h3>

              <p>
                Enter a URL and start an investigation to view its risk
                assessment, findings, DNS information, and available threat
                intelligence.
              </p>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

// Email Analysis Page
function EmailAnalysisPage() {
  const [activeTab, setActiveTab] = useState("address");

  const [emailAddress, setEmailAddress] = useState("");
  const [emailContent, setEmailContent] = useState("");

  const [addressResult, setAddressResult] = useState(null);
  const [contentResult, setContentResult] = useState(null);

  const [addressLoading, setAddressLoading] = useState(false);
  const [contentLoading, setContentLoading] = useState(false);

  const [addressError, setAddressError] = useState("");
  const [contentError, setContentError] = useState("");

  async function handleAddressAnalyze(event) {
    event.preventDefault();

    setAddressError("");
    setAddressResult(null);

    const cleanedAddress = emailAddress.trim();

    if (!cleanedAddress) {
      setAddressError("Please enter an email address.");
      return;
    }

    setAddressLoading(true);

    try {
      const data = await requestAPI("/analyze-email-address", {
        email: cleanedAddress,
      });

      console.log("Email address analysis response:", data);
      console.log("Email reputation intelligence:", data.reputation_intelligence);

      setAddressResult(data);
    } catch (err) {
      setAddressError(
        err.message || "Email address analysis failed."
      );
    } finally {
      setAddressLoading(false);
    }
  }

  async function handleContentAnalyze(event) {
    event.preventDefault();

    setContentError("");
    setContentResult(null);

    const cleanedContent = emailContent.trim();

    if (!cleanedContent) {
      setContentError("Please enter email content to analyze.");
      return;
    }

    setContentLoading(true);

    try {
      const data = await requestAPI("/analyze-email", {
        email_text: cleanedContent,
      });

      setContentResult(data);
    } catch (err) {
      setContentError(
        err.message || "Email content analysis failed."
      );
    } finally {
      setContentLoading(false);
    }
  }

  return (
    <div className="analysis-page">
      <div className="page-header">
        <span className="page-eyebrow">INVESTIGATION TOOL</span>
        <h1>Email Analysis</h1>

        <p>
          Investigate suspicious email addresses and examine email messages
          for phishing indicators.
        </p>
      </div>

      <div className="email-analysis-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          id="email-address-tab"
          aria-selected={activeTab === "address"}
          className={`email-analysis-tab ${
            activeTab === "address" ? "active" : ""
          }`}
          onClick={() => setActiveTab("address")}
        >
          <Mail size={19} />
          Email Address Analysis
        </button>

        <button
          type="button"
          role="tab"
          id="email-content-tab"
          aria-selected={activeTab === "content"}
          className={`email-analysis-tab ${
            activeTab === "content" ? "active" : ""
          }`}
          onClick={() => setActiveTab("content")}
        >
          <Search size={19} />
          Email Content Analysis
        </button>
      </div>

      {activeTab === "address" && (
        <div
          className="analysis-layout"
          role="tabpanel"
          aria-labelledby="email-address-tab"
        >
          <section className="analysis-form-panel">
            <div className="form-panel-heading">
              <div className="form-panel-icon">
                <Mail size={23} />
              </div>

              <div>
                <h2>Investigate an Email Address</h2>
                <p>
                  Enter the sender address you want to investigate.
                </p>
              </div>
            </div>

            <form onSubmit={handleAddressAnalyze}>
              <label htmlFor="email-address-input">Email Address</label>

              <div className="input-with-icon">
                <Mail size={19} />

                <input
                  id="email-address-input"
                  type="email"
                  value={emailAddress}
                  onChange={(event) =>
                    setEmailAddress(event.target.value)
                  }
                  placeholder="security@example.com"
                  autoComplete="off"
                  required
                />
              </div>

              <button
                type="submit"
                className="primary-button analyze-button"
                disabled={addressLoading}
              >
                {addressLoading ? (
                  <>
                    <LoaderCircle size={18} className="spin-icon" />
                    Investigating Address...
                  </>
                ) : (
                  <>
                    <Search size={18} />
                    Analyze Email Address
                  </>
                )}
              </button>
            </form>

            {addressError && (
              <div className="error-message">
                <XCircle size={19} />
                <p>{addressError}</p>
              </div>
            )}

            <p className="form-safety-note">
              Address analysis can inspect domain configuration and
              available reputation indicators. It cannot independently
              confirm mailbox ownership.
            </p>
          </section>

          <div>
            {addressResult ? (
              <AnalysisResult
                result={addressResult}
                type="email-address"
              />
            ) : (
              <section className="result-panel empty-result">
                <Mail size={28} />
                <h3>Address Analysis Results</h3>

                <p>
                  Enter an email address to investigate its domain
                  configuration and available security indicators.
                </p>
              </section>
            )}
          </div>
        </div>
      )}

      {activeTab === "content" && (
        <div
          className="analysis-layout"
          role="tabpanel"
          aria-labelledby="email-content-tab"
        >
          <section className="analysis-form-panel">
            <div className="form-panel-heading">
              <div className="form-panel-icon">
                <Search size={23} />
              </div>

              <div>
                <h2>Investigate Email Content</h2>
                <p>Paste the suspicious message below.</p>
              </div>
            </div>

            <form onSubmit={handleContentAnalyze}>
              <label htmlFor="email-content-input">
                Email Content
              </label>

              <textarea
                id="email-content-input"
                className="email-textarea"
                value={emailContent}
                onChange={(event) =>
                  setEmailContent(event.target.value)
                }
                placeholder="Paste the suspicious email message here..."
                rows={8}
                required
              />

              <button
                type="submit"
                className="primary-button analyze-button"
                disabled={contentLoading}
              >
                {contentLoading ? (
                  <>
                    <LoaderCircle size={18} className="spin-icon" />
                    Analyzing Content...
                  </>
                ) : (
                  <>
                    <Search size={18} />
                    Analyze Email Content
                  </>
                )}
              </button>
            </form>

            {contentError && (
              <div className="error-message">
                <XCircle size={19} />
                <p>{contentError}</p>
              </div>
            )}

            <p className="form-safety-note">
              Remove passwords, private information, and other sensitive
              data before submitting email content.
            </p>
          </section>

          <div>
            {contentResult ? (
              <AnalysisResult
                result={contentResult}
                type="email"
              />
            ) : (
              <section className="result-panel empty-result">
                <Mail size={28} />
                <h3>Content Analysis Results</h3>

                <p>
                  Submit email content to view the risk assessment and
                  phishing indicators returned by the analyzer.
                </p>
              </section>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Main Application
function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navigation = [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: LayoutDashboard,
    },
    {
      id: "url",
      label: "URL Analysis",
      icon: LinkIcon,
    },
    {
      id: "email",
      label: "Email Analysis",
      icon: Mail,
    },
    {
      id: "password",
      label: "Password Checker",
      icon: LockKeyhole,
    },
  ];

  function changePage(page) {
    setActivePage(page);
    setSidebarOpen(false);
  }

  function renderPage() {
    switch (activePage) {
      case "url":
        return <URLAnalysisPage />;

      case "email":
        return <EmailAnalysisPage />;

      case "password":
        return <PasswordChecker />;

      case "dashboard":
      default:
        return <DashboardPage setPage={changePage} />;
    }
  }

  const currentPage =
    navigation.find((item) => item.id === activePage)?.label ||
    "Dashboard";

  return (
    <div className="app-container">
      {sidebarOpen && (
        <button
          className="sidebar-overlay"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}
      >
        <div className="sidebar-brand">
          <div className="brand-icon">
            <ShieldCheck size={27} />
          </div>

          <div className="brand-text">
            <h2>PhishGuard</h2>
            <span>PRO SECURITY</span>
          </div>

          <button
            className="sidebar-close"
            aria-label="Close navigation"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-section-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.id}
                className={`nav-item ${
                  activePage === item.id ? "active" : ""
                }`}
                onClick={() => changePage(item.id)}
              >
                <Icon size={19} />
                <span>{item.label}</span>

                {activePage === item.id && (
                  <span className="nav-active-indicator" />
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-security-card">
            <div className="sidebar-security-icon">
              <ShieldCheck size={20} />
            </div>

            <div>
              <strong>Security First</strong>
              <p>Investigate suspicious activity responsibly.</p>
            </div>
          </div>

          <div className="sidebar-footer">
            <div className="footer-status-icon">
              <Activity size={18} />
            </div>

            <div>
              <p>Backend status</p>
              <span>Security Workspace</span>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="menu-button"
              aria-label="Open navigation"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu size={22} />
            </button>

            <div className="breadcrumb">
              <span>PhishGuard Pro</span>
              <span className="breadcrumb-divider">/</span>
              <strong>{currentPage}</strong>
            </div>
          </div>

          <div className="topbar-right">
            <span className="topbar-status-dot" />

            <span className="topbar-status-text">
              Security Workspace
            </span>

            <div className="topbar-avatar">
              <ShieldCheck size={18} />
            </div>
          </div>
        </header>

        <div className="main-content">{renderPage()}</div>

        <footer className="app-footer">
          <span>PhishGuard Pro</span>
          <span>Cybersecurity Investigation Toolkit</span>
        </footer>
      </main>
    </div>
  );
}

export default App;