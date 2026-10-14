
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  LayoutDashboard,
  Link as LinkIcon,
  Mail,
  History,
  FileText,
  Menu,
  X,
  ArrowRight,
  ExternalLink,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  Globe,
  Eye,
  ChevronRight,
  LockKeyhole,
  Bug,
  CircleHelp,
  Server,
  Database,
  ArrowLeft,
} from "lucide-react";

import "./App.css";

const API_URL = "/api";

/* -------------------- HELPERS -------------------- */

function formatDate(date) {
  if (!date) return "Unknown date";

  const parsedDate = new Date(date);

  if (Number.isNaN(parsedDate.getTime())) {
    return String(date);
  }

  return parsedDate.toLocaleString();
}

function getRiskClass(level) {
  const risk = String(level || "unknown").toLowerCase();

  if (risk === "high" || risk === "critical") return "high";
  if (risk === "medium" || risk === "moderate") return "medium";
  if (risk === "low") return "low";

  return "unknown";
}

function getRiskIcon(level) {
  const risk = String(level || "").toLowerCase();

  if (risk === "high" || risk === "critical") {
    return <ShieldAlert size={18} />;
  }

  if (risk === "medium" || risk === "moderate") {
    return <AlertTriangle size={18} />;
  }

  return <ShieldCheck size={18} />;
}

function getTarget(item) {
  return (
    item?.target ||
    item?.url ||
    item?.email ||
    item?.sender ||
    item?.subject ||
    "Unknown target"
  );
}

function getScore(item) {
  const score = Number(
    item?.risk_score ??
      item?.score ??
      item?.result?.risk_score ??
      item?.result_json?.risk_score ??
      0
  );

  return Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
}

function getLevel(item) {
  return (
    item?.risk_level ||
    item?.result?.risk_level ||
    item?.result_json?.risk_level ||
    "Unknown"
  );
}

function getResultData(item) {
  if (!item) return {};

  if (typeof item.result_json === "string") {
    try {
      return JSON.parse(item.result_json);
    } catch {
      return item;
    }
  }

  if (
    item.result_json &&
    typeof item.result_json === "object"
  ) {
    return item.result_json;
  }

  if (item.result && typeof item.result === "object") {
    return item.result;
  }

  if (item.analysis && typeof item.analysis === "object") {
    return item.analysis;
  }

  return item;
}

function getFindings(item) {
  const data = getResultData(item);

  if (Array.isArray(data.findings)) {
    return data.findings;
  }

  if (Array.isArray(item?.findings)) {
    return item.findings;
  }

  return [];
}

function getFindingTitle(finding) {
  if (typeof finding === "string") return finding;

  return (
    finding?.title ||
    finding?.name ||
    finding?.type ||
    finding?.category ||
    "Security finding"
  );
}

function getFindingDescription(finding) {
  if (typeof finding === "string") return finding;

  return (
    finding?.description ||
    finding?.message ||
    finding?.details ||
    finding?.evidence ||
    "No additional details provided."
  );
}

function getFindingSeverity(finding) {
  if (typeof finding === "string") return "info";

  return (
    finding?.severity ||
    finding?.risk ||
    finding?.level ||
    "info"
  );
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "Not available";
  }

  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "None found";
  }

  if (typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value);
}

/* -------------------- SHARED COMPONENTS -------------------- */

function StatCard({ title, value, description, icon, color }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${color || ""}`}>{icon}</div>

      <div className="stat-content">
        <p>{title}</p>
        <h2>{value ?? 0}</h2>
        {description && <span>{description}</span>}
      </div>
    </div>
  );
}

function RiskBadge({ level }) {
  const riskClass = getRiskClass(level);

  return (
    <span className={`risk-badge risk-${riskClass}`}>
      {getRiskIcon(level)}
      <span>{level || "Unknown"}</span>
    </span>
  );
}

function EmptyState({ icon, title, description }) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon">
        {icon || <Database size={30} />}
      </div>

      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

function LoadingState({ message = "Analyzing security data..." }) {
  return (
    <div className="loading-state">
      <div className="loading-spinner" />
      <p>{message}</p>
    </div>
  );
}

function ErrorMessage({ message, onRetry }) {
  if (!message) return null;

  return (
    <div className="error-message">
      <AlertTriangle size={20} />

      <div>
        <strong>Something went wrong</strong>
        <p>{message}</p>

        {onRetry && (
          <button className="text-button" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    </div>
  );
}

function RiskScoreCard({ result }) {
  const score = getScore(result);
  const level = getLevel(result);
  const riskClass = getRiskClass(level);

  return (
    <section className="panel risk-score-panel">
      <div className="section-heading">
        <div>
          <h3>Threat Assessment</h3>
          <p>Overall security risk evaluation</p>
        </div>

        <RiskBadge level={level} />
      </div>

      <div className="risk-score-layout">
        <div className={`risk-score-circle risk-circle-${riskClass}`}>
          <div className="risk-score-inner">
            <strong>{score}</strong>
            <span>out of 100</span>
          </div>
        </div>

        <div className="risk-score-details">
          <h4>{level} Risk</h4>

          <p>
            {score >= 70
              ? "Multiple indicators suggest a potentially dangerous target. Exercise extreme caution."
              : score >= 40
                ? "Some suspicious indicators were detected. Review the findings before interacting with this target."
                : score >= 20
                  ? "A few indicators require attention. Review the analysis before trusting this target."
                  : "Few risk indicators were identified by the current checks. This does not guarantee safety."}
          </p>

          <div className="risk-progress">
            <div
              className={`risk-progress-fill risk-fill-${riskClass}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>
      </div>
    </section>
  );
}

function FindingsList({ result }) {
  const findings = getFindings(result);

  return (
    <section className="panel findings-panel">
      <div className="section-heading">
        <div>
          <h3>Analysis Findings</h3>
          <p>Indicators identified during the investigation</p>
        </div>

        <span className="findings-count">{findings.length} findings</span>
      </div>

      {findings.length === 0 ? (
        <EmptyState
          icon={<CheckCircle size={28} />}
          title="No findings returned"
          description="The analyzer did not report any findings. This does not prove the target is safe."
        />
      ) : (
        <div className="findings-list">
          {findings.map((finding, index) => {
            const severity = getFindingSeverity(finding);

            return (
              <div className="finding-item" key={index}>
                <div className={`finding-icon severity-${getRiskClass(severity)}`}>
                  {getRiskIcon(severity)}
                </div>

                <div className="finding-content">
                  <div className="finding-title-row">
                    <h4>{getFindingTitle(finding)}</h4>

                    <span
                      className={`severity-badge severity-${getRiskClass(
                        severity
                      )}`}
                    >
                      {severity}
                    </span>
                  </div>

                  <p>{getFindingDescription(finding)}</p>

                  {finding?.points !== undefined && (
                    <span className="finding-points">
                      Risk points: {finding.points}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

/* -------------------- INTELLIGENCE PANELS -------------------- */

function ThreatIntelligencePanel({ threat }) {
  if (!threat) {
    return (
      <section className="panel intelligence-panel">
        <div className="intelligence-heading">
          <div className="intelligence-icon threat-icon">
            <ShieldCheck size={22} />
          </div>

          <div>
            <h3>Threat Intelligence</h3>
            <p>External phishing database lookup</p>
          </div>
        </div>

        <p className="intelligence-empty">
          No threat intelligence data was returned.
        </p>
      </section>
    );
  }

  const available = threat.available === true;
  const knownPhishing = threat.known_phishing === true;

  return (
    <section className="panel intelligence-panel">
      <div className="intelligence-heading">
        <div className="intelligence-icon threat-icon">
          <ShieldCheck size={22} />
        </div>

        <div>
          <h3>Threat Intelligence</h3>
          <p>{threat.provider || "External threat database"}</p>
        </div>
      </div>

      <div className="intelligence-grid">
        <div className="intelligence-item">
          <span>Provider</span>
          <strong>{displayValue(threat.provider)}</strong>
        </div>

        <div className="intelligence-item">
          <span>Lookup Status</span>
          <strong className={available ? "status-good" : "status-warning"}>
            {available ? "Available" : "Unavailable"}
          </strong>
        </div>

        <div className="intelligence-item">
          <span>Phishing Database Match</span>
          <strong
            className={
              !available
                ? "status-warning"
                : knownPhishing
                  ? "status-danger"
                  : "status-good"
            }
          >
            {!available
              ? "Unable to verify"
              : knownPhishing
                ? "Match Found"
                : "No Match Found"}
          </strong>
        </div>

        <div className="intelligence-item">
          <span>Target Brand</span>
          <strong>{displayValue(threat.target_brand)}</strong>
        </div>

        <div className="intelligence-item">
          <span>Threat Status</span>
          <strong>{displayValue(threat.status)}</strong>
        </div>
      </div>

      <div className="intelligence-message">
        <p>
          {threat.message ||
            "The provider did not return an explanation."}
        </p>
      </div>

      {!available && (
        <p className="intelligence-note">
          The threat database could not be reached. This is an inconclusive
          result, not evidence that the target is safe.
        </p>
      )}
    </section>
  );
}

function DNSIntelligencePanel({ dns }) {
  if (!dns) {
    return (
      <section className="panel intelligence-panel">
        <div className="intelligence-heading">
          <div className="intelligence-icon dns-icon">
            <Server size={22} />
          </div>

          <div>
            <h3>DNS Intelligence</h3>
            <p>Domain infrastructure information</p>
          </div>
        </div>

        <p className="intelligence-empty">
          No DNS intelligence data was returned.
        </p>
      </section>
    );
  }

  return (
    <section className="panel intelligence-panel">
      <div className="intelligence-heading">
        <div className="intelligence-icon dns-icon">
          <Server size={22} />
        </div>

        <div>
          <h3>DNS Intelligence</h3>
          <p>Domain infrastructure information</p>
        </div>
      </div>

      <div className="intelligence-grid">
        <div className="intelligence-item">
          <span>Hostname</span>
          <strong>{displayValue(dns.hostname)}</strong>
        </div>

        <div className="intelligence-item">
          <span>Lookup Status</span>
          <strong className={dns.available ? "status-good" : "status-warning"}>
            {dns.available ? "Available" : "Unavailable"}
          </strong>
        </div>

        <div className="intelligence-item">
          <span>IPv4 Addresses</span>
          <strong>{displayValue(dns.ip_addresses)}</strong>
        </div>

        <div className="intelligence-item">
          <span>IPv6 Addresses</span>
          <strong>{displayValue(dns.ipv6_addresses)}</strong>
        </div>

        <div className="intelligence-item">
          <span>Mail Exchange Records</span>
          <strong>{displayValue(dns.mx_records)}</strong>
        </div>

        <div className="intelligence-item">
          <span>Nameservers</span>
          <strong>{displayValue(dns.nameservers)}</strong>
        </div>
      </div>

      <div className="dns-findings">
        <h4>DNS Findings</h4>

        {Array.isArray(dns.findings) && dns.findings.length > 0 ? (
          <ul>
            {dns.findings.map((finding, index) => (
              <li key={index}>
                {typeof finding === "string"
                  ? finding
                  : finding.message ||
                    finding.description ||
                    JSON.stringify(finding)}
              </li>
            ))}
          </ul>
        ) : (
          <p>No additional DNS findings were reported.</p>
        )}
      </div>
    </section>
  );
}

/* -------------------- COMPLETE ANALYSIS RESULT -------------------- */

function AnalysisResult({ result }) {
  if (!result) return null;

  const data = getResultData(result);
  const target = getTarget({ ...data, ...result });
  const isUrlAnalysis =
    Boolean(data.url || result.url) &&
    !result.analysis_type?.toLowerCase().includes("email");

  const threat = data.threat_intelligence;
  const dns = data.dns_intelligence;

  return (
    <div className="analysis-result">
      <div className="panel result-target-panel">
        <div className="result-target-icon">
          {isUrlAnalysis ? <Globe size={22} /> : <Mail size={22} />}
        </div>

        <div className="result-target-content">
          <p>Investigated Target</p>
          <h3>{target}</h3>

          {result.id && (
            <span className="investigation-id">
              Investigation ID: #{result.id}
            </span>
          )}
        </div>
      </div>

      <RiskScoreCard result={{ ...data, ...result }} />

      <FindingsList result={data} />

      {isUrlAnalysis && <ThreatIntelligencePanel threat={threat} />}

      {isUrlAnalysis && <DNSIntelligencePanel dns={dns} />}

      <div className="disclaimer-box">
        <CircleHelp size={20} />

        <div>
          <strong>Important Security Notice</strong>
          <p>
            This assessment combines heuristic checks with available external
            intelligence. A URL not found in a threat database is not
            necessarily safe. HTTPS does not prove a website is legitimate,
            and DNS records alone cannot establish whether a domain is
            malicious or trustworthy.
          </p>
        </div>
      </div>
    </div>
  );
}

/* -------------------- DASHBOARD -------------------- */

function DashboardPage({ history, onNavigate, loading }) {
  const total = history.length;

  const highRisk = history.filter((item) => {
    const level = String(getLevel(item)).toLowerCase();
    return level === "high" || level === "critical";
  }).length;

  const lowRisk = history.filter(
    (item) => String(getLevel(item)).toLowerCase() === "low"
  ).length;

  const mediumRisk = history.filter((item) => {
    const level = String(getLevel(item)).toLowerCase();
    return level === "medium" || level === "moderate";
  }).length;

  const recentInvestigations = history.slice(0, 5);

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <span className="eyebrow">SECURITY OVERVIEW</span>
          <h1>Dashboard</h1>
          <p>Monitor your phishing investigations and security findings.</p>
        </div>

        <button
          className="primary-button"
          onClick={() => onNavigate("url-analysis")}
        >
          <Search size={18} />
          New Investigation
        </button>
      </div>

      <div className="stats-grid">
        <StatCard
          title="Total Investigations"
          value={total}
          description="Saved investigations"
          icon={<Activity size={22} />}
          color="blue"
        />

        <StatCard
          title="High Risk"
          value={highRisk}
          description="Requires attention"
          icon={<ShieldAlert size={22} />}
          color="red"
        />

        <StatCard
          title="Medium Risk"
          value={mediumRisk}
          description="Review recommended"
          icon={<AlertTriangle size={22} />}
          color="orange"
        />

        <StatCard
          title="Low Risk"
          value={lowRisk}
          description="Fewer detected indicators"
          icon={<ShieldCheck size={22} />}
          color="green"
        />
      </div>

      <div className="dashboard-grid">
        <section className="panel dashboard-main-panel">
          <div className="section-heading">
            <div>
              <h3>Recent Investigations</h3>
              <p>Your latest saved analysis results</p>
            </div>

            <button
              className="text-button"
              onClick={() => onNavigate("history")}
            >
              View all <ArrowRight size={16} />
            </button>
          </div>

          {loading ? (
            <LoadingState message="Loading investigations..." />
          ) : recentInvestigations.length === 0 ? (
            <EmptyState
              icon={<History size={28} />}
              title="No investigations yet"
              description="Start by analyzing a suspicious URL or email."
            />
          ) : (
            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Type</th>
                    <th>Risk</th>
                    <th>Date</th>
                    <th />
                  </tr>
                </thead>

                <tbody>
                  {recentInvestigations.map((item) => (
                    <tr key={item.id}>
                      <td className="target-cell">
                        <span>{getTarget(item)}</span>
                      </td>

                      <td>
                        {item.analysis_type || item.type || "Analysis"}
                      </td>

                      <td>
                        <RiskBadge level={getLevel(item)} />
                      </td>

                      <td>{formatDate(item.created_at)}</td>

                      <td>
                        <button
                          className="icon-button"
                          title="View investigation"
                          onClick={() => onNavigate("details", item.id)}
                        >
                          <ChevronRight size={18} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="panel quick-actions-panel">
          <div className="section-heading">
            <div>
              <h3>Quick Actions</h3>
              <p>Start a new security check</p>
            </div>
          </div>

          <button
            className="quick-action"
            onClick={() => onNavigate("url-analysis")}
          >
            <span className="quick-action-icon blue">
              <LinkIcon size={21} />
            </span>

            <span>
              <strong>Analyze URL</strong>
              <small>Check a suspicious website</small>
            </span>

            <ChevronRight size={18} />
          </button>

          <button
            className="quick-action"
            onClick={() => onNavigate("email-analysis")}
          >
            <span className="quick-action-icon purple">
              <Mail size={21} />
            </span>

            <span>
              <strong>Analyze Email</strong>
              <small>Inspect suspicious email text</small>
            </span>

            <ChevronRight size={18} />
          </button>

          <button
            className="quick-action"
            onClick={() => onNavigate("history")}
          >
            <span className="quick-action-icon green">
              <History size={21} />
            </span>

            <span>
              <strong>Investigation History</strong>
              <small>Review saved investigations</small>
            </span>

            <ChevronRight size={18} />
          </button>
        </section>
      </div>

      <section className="panel overview-panel">
        <div className="section-heading">
          <div>
            <h3>Platform Capabilities</h3>
            <p>Security checks available in PhishGuard Pro</p>
          </div>
        </div>

        <div className="capabilities-grid">
          <div className="capability-item">
            <div className="capability-icon">
              <Globe size={22} />
            </div>
            <h4>URL Analysis</h4>
            <p>Inspect suspicious URL patterns and domain indicators.</p>
          </div>

          <div className="capability-item">
            <div className="capability-icon">
              <ShieldCheck size={22} />
            </div>
            <h4>Threat Intelligence</h4>
            <p>Check URL information against the OpenPhish database.</p>
          </div>

          <div className="capability-item">
            <div className="capability-icon">
              <Server size={22} />
            </div>
            <h4>DNS Intelligence</h4>
            <p>Review domain IP addresses, mail records, and nameservers.</p>
          </div>

          <div className="capability-item">
            <div className="capability-icon">
              <FileText size={22} />
            </div>
            <h4>Investigation Reports</h4>
            <p>Review saved results and export available PDF reports.</p>
          </div>
        </div>
      </section>
    </div>
  );
}

/* -------------------- URL ANALYSIS -------------------- */

function URLAnalysisPage({ onResultSaved }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();

    const value = url.trim();

    if (!value) {
      setError("Please enter a URL to analyze.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/analyze-url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: value }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || data.message || "URL analysis failed."
        );
      }

      const analysis = data.result || data.analysis || data;

      setResult(analysis);

      if (data.investigation_id && !analysis.id) {
        analysis.id = data.investigation_id;
      }

      await onResultSaved();
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to the backend. Check that Flask is running."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <span className="eyebrow">WEBSITE SECURITY</span>
          <h1>URL Analysis</h1>
          <p>Inspect a URL for suspicious patterns and phishing indicators.</p>
        </div>
      </div>

      <section className="panel analysis-form-panel">
        <div className="form-intro-icon">
          <Globe size={25} />
        </div>

        <h3>Analyze a Website</h3>

        <p>
          Enter a website address to perform heuristic, DNS, and available
          threat-intelligence checks.
        </p>

        <form onSubmit={handleSubmit} className="analysis-form">
          <label htmlFor="url-input">Website URL</label>

          <div className="input-with-icon">
            <LinkIcon size={19} />

            <input
              id="url-input"
              type="text"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com"
              autoComplete="url"
            />
          </div>

          <p className="form-hint">
            Enter a URL you want to inspect. Do not visit suspicious websites
            directly.
          </p>

          <button
            type="submit"
            className="primary-button full-width"
            disabled={loading}
          >
            {loading ? (
              <>
                <RefreshCw size={18} className="spinning" />
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

        {error && <ErrorMessage message={error} />}
      </section>

      {loading && <LoadingState message="Inspecting URL and domain intelligence..." />}

      {result && (
        <div className="result-section">
          <div className="section-heading result-section-heading">
            <div>
              <h2>Analysis Results</h2>
              <p>Review the findings for this investigation.</p>
            </div>

            <button
              className="secondary-button"
              onClick={() => {
                setResult(null);
                setUrl("");
                setError("");
              }}
            >
              <RefreshCw size={16} />
              New Analysis
            </button>
          </div>

          <AnalysisResult result={result} />
        </div>
      )}
    </div>
  );
}

/* -------------------- EMAIL ANALYSIS -------------------- */

function EmailAnalysisPage({ onResultSaved }) {
  const [emailText, setEmailText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();

    const value = emailText.trim();

    if (!value) {
      setError("Please paste email content to analyze.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/analyze-email`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email_text: value,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || data.message || "Email analysis failed."
        );
      }

      const analysis = data.result || data.analysis || data;

      setResult(analysis);

      if (data.investigation_id && !analysis.id) {
        analysis.id = data.investigation_id;
      }

      await onResultSaved();
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to the backend. Check that Flask is running."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <span className="eyebrow">EMAIL SECURITY</span>
          <h1>Email Analysis</h1>
          <p>Inspect suspicious email content for potential phishing indicators.</p>
        </div>
      </div>

      <section className="panel analysis-form-panel">
        <div className="form-intro-icon purple">
          <Mail size={25} />
        </div>

        <h3>Analyze an Email</h3>

        <p>
          Paste the email text, including its sender information, subject, and
          message body when available.
        </p>

        <form onSubmit={handleSubmit} className="analysis-form">
          <label htmlFor="email-input">Email Content</label>

          <textarea
            id="email-input"
            value={emailText}
            onChange={(event) => setEmailText(event.target.value)}
            placeholder={`From: security@example.com
Subject: Verify your account

Paste the email message here...`}
            rows={10}
          />

          <p className="form-hint">
            Avoid pasting real passwords, OTPs, private information, or other
            sensitive data.
          </p>

          <button
            type="submit"
            className="primary-button full-width"
            disabled={loading}
          >
            {loading ? (
              <>
                <RefreshCw size={18} className="spinning" />
                Analyzing Email...
              </>
            ) : (
              <>
                <Search size={18} />
                Analyze Email
              </>
            )}
          </button>
        </form>

        {error && <ErrorMessage message={error} />}
      </section>

      {loading && <LoadingState message="Inspecting email content..." />}

      {result && (
        <div className="result-section">
          <div className="section-heading result-section-heading">
            <div>
              <h2>Analysis Results</h2>
              <p>Review the findings for this email.</p>
            </div>

            <button
              className="secondary-button"
              onClick={() => {
                setResult(null);
                setEmailText("");
                setError("");
              }}
            >
              <RefreshCw size={16} />
              New Analysis
            </button>
          </div>

          <AnalysisResult
            result={{
              ...result,
              analysis_type: "email",
              target:
                result.target ||
                result.subject ||
                "Email content analysis",
            }}
          />
        </div>
      )}
    </div>
  );
}

/* -------------------- INVESTIGATION HISTORY -------------------- */

function InvestigationHistoryPage({
  history,
  loading,
  onRefresh,
  onNavigate,
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");

  const filteredHistory = history.filter((item) => {
    const target = getTarget(item).toLowerCase();
    const search = searchTerm.toLowerCase();

    const matchesSearch = target.includes(search);

    const level = String(getLevel(item)).toLowerCase();

    const matchesRisk =
      riskFilter === "all" ||
      (riskFilter === "high" &&
        (level === "high" || level === "critical")) ||
      (riskFilter === "medium" &&
        (level === "medium" || level === "moderate")) ||
      (riskFilter === "low" && level === "low");

    return matchesSearch && matchesRisk;
  });

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <span className="eyebrow">INVESTIGATION RECORDS</span>
          <h1>Investigation History</h1>
          <p>Search and review your previously saved investigations.</p>
        </div>

        <button
          className="secondary-button"
          onClick={onRefresh}
          disabled={loading}
        >
          <RefreshCw size={17} className={loading ? "spinning" : ""} />
          Refresh
        </button>
      </div>

      <section className="panel history-panel">
        <div className="history-toolbar">
          <div className="search-field">
            <Search size={18} />

            <input
              type="search"
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Search targets..."
            />
          </div>

          <select
            value={riskFilter}
            onChange={(event) => setRiskFilter(event.target.value)}
            aria-label="Filter by risk level"
          >
            <option value="all">All Risk Levels</option>
            <option value="high">High Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="low">Low Risk</option>
          </select>
        </div>

        {loading ? (
          <LoadingState message="Loading investigation history..." />
        ) : filteredHistory.length === 0 ? (
          <EmptyState
            icon={<History size={28} />}
            title="No matching investigations"
            description="Try another search or run a new analysis."
          />
        ) : (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Analysis Type</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>Date</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {filteredHistory.map((item) => (
                  <tr key={item.id}>
                    <td>#{item.id}</td>

                    <td className="target-cell">
                      <span>{getTarget(item)}</span>
                    </td>

                    <td>{item.analysis_type || item.type || "Analysis"}</td>

                    <td>{getScore(item)}/100</td>

                    <td>
                      <RiskBadge level={getLevel(item)} />
                    </td>

                    <td>{formatDate(item.created_at)}</td>

                    <td>
                      <button
                        className="secondary-button small-button"
                        onClick={() => onNavigate("details", item.id)}
                      >
                        View <ChevronRight size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="table-footer">
          Showing {filteredHistory.length} of {history.length} investigations
        </div>
      </section>
    </div>
  );
}

/* -------------------- REPORTS -------------------- */

function ReportsPage({ history, onNavigate }) {
  const [downloadingId, setDownloadingId] = useState(null);
  const [error, setError] = useState("");

  async function downloadReport(item) {
    setDownloadingId(item.id);
    setError("");

    try {
      const response = await fetch(
        `${API_URL}/reports/${item.id}/pdf`
      );

      if (!response.ok) {
        let message = "Unable to download the PDF report.";

        try {
          const data = await response.json();
          message = data.error || data.message || message;
        } catch {
          // The response may not contain JSON.
        }

        throw new Error(message);
      }

      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);

      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `phishguard-report-${item.id}.pdf`;

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      window.URL.revokeObjectURL(objectUrl);
    } catch (err) {
      setError(err.message || "Report download failed.");
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <span className="eyebrow">DOCUMENTATION</span>
          <h1>Security Reports</h1>
          <p>Download PDF reports for saved investigations.</p>
        </div>
      </div>

      {error && <ErrorMessage message={error} />}

      <section className="panel reports-panel">
        <div className="section-heading">
          <div>
            <h3>Available Reports</h3>
            <p>Reports are generated from saved investigation records.</p>
          </div>

          <span className="findings-count">{history.length} records</span>
        </div>

        {history.length === 0 ? (
          <EmptyState
            icon={<FileText size={28} />}
            title="No reports available"
            description="Run an analysis first to create an investigation report."
          />
        ) : (
          <div className="reports-list">
            {history.map((item) => (
              <div className="report-item" key={item.id}>
                <div className="report-file-icon">
                  <FileText size={23} />
                </div>

                <div className="report-info">
                  <h4>Investigation Report #{item.id}</h4>
                  <p>{getTarget(item)}</p>

                  <div className="report-meta">
                    <span>{formatDate(item.created_at)}</span>
                    <RiskBadge level={getLevel(item)} />
                  </div>
                </div>

                <div className="report-actions">
                  <button
                    className="icon-button"
                    title="View investigation"
                    onClick={() => onNavigate("details", item.id)}
                  >
                    <Eye size={18} />
                  </button>

                  <button
                    className="primary-button small-button"
                    disabled={downloadingId === item.id}
                    onClick={() => downloadReport(item)}
                  >
                    {downloadingId === item.id ? (
                      <RefreshCw size={16} className="spinning" />
                    ) : (
                      <Download size={16} />
                    )}

                    {downloadingId === item.id ? "Preparing..." : "Download PDF"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

/* -------------------- INVESTIGATION DETAILS -------------------- */

function InvestigationDetailsPage({
  investigationId,
  onBack,
}) {
  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadInvestigation() {
      setLoading(true);
      setError("");

      try {
        const response = await fetch(
          `${API_URL}/history/${investigationId}`
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(
            data.error ||
              data.message ||
              "Unable to load investigation details."
          );
        }

        const record =
          data.investigation ||
          data.result ||
          data;

        if (!cancelled) {
          setInvestigation(record);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err.message ||
              "Unable to connect to the backend."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    if (investigationId !== undefined && investigationId !== null) {
      loadInvestigation();
    } else {
      setError("No investigation ID was provided.");
      setLoading(false);
    }

    return () => {
      cancelled = true;
    };
  }, [investigationId]);

  if (loading) {
    return (
      <div className="page-content">
        <LoadingState message="Loading investigation details..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-content">
        <button className="secondary-button" onClick={onBack}>
          <ArrowLeft size={17} />
          Back
        </button>

        <ErrorMessage message={error} />
      </div>
    );
  }

  if (!investigation) {
    return (
      <div className="page-content">
        <EmptyState
          icon={<Database size={28} />}
          title="Investigation not found"
          description="This investigation may no longer be available."
        />

        <button className="secondary-button" onClick={onBack}>
          <ArrowLeft size={17} />
          Back
        </button>
      </div>
    );
  }

  const data = getResultData(investigation);

  const mergedResult = {
    ...data,
    ...investigation,
    ...(
      investigation.result_json
        ? data
        : {}
    ),
    id: investigation.id,
    target: investigation.target || getTarget(data),
    risk_score:
      investigation.risk_score ?? data.risk_score,
    risk_level:
      investigation.risk_level ?? data.risk_level,
    analysis_type:
      investigation.analysis_type || data.analysis_type,
  };

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <span className="eyebrow">SAVED RECORD</span>
          <h1>Investigation Details</h1>
          <p>
            Investigation #{investigation.id} ·{" "}
            {formatDate(investigation.created_at)}
          </p>
        </div>

        <button className="secondary-button" onClick={onBack}>
          <ArrowLeft size={17} />
          Back to History
        </button>
      </div>

      <AnalysisResult result={mergedResult} />
    </div>
  );
}

/* -------------------- APPLICATION -------------------- */

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [selectedInvestigationId, setSelectedInvestigationId] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);

  async function loadHistory() {
    setHistoryLoading(true);
    setHistoryError("");

    try {
      const response = await fetch(`${API_URL}/history`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
            data.message ||
            "Unable to load investigation history."
        );
      }

      const records = Array.isArray(data)
        ? data
        : data.history ||
          data.investigations ||
          data.results ||
          [];

      setHistory(records);
    } catch (err) {
      setHistoryError(
        err.message ||
          "Unable to connect to the Flask backend."
      );
    } finally {
      setHistoryLoading(false);
    }
  }

  async function checkBackend() {
    try {
      const response = await fetch(`${API_URL.replace("/api", "")}/api/health`);
      setBackendOnline(response.ok);
    } catch {
      setBackendOnline(false);
    }
  }

  useEffect(() => {
    loadHistory();
    checkBackend();
  }, []);

  function navigateTo(page, investigationId = null) {
    setActivePage(page);
    setSidebarOpen(false);

    if (page === "details") {
      setSelectedInvestigationId(investigationId);
    } else {
      setSelectedInvestigationId(null);
    }

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  }

  const navItems = [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: <LayoutDashboard size={19} />,
    },
    {
      id: "url-analysis",
      label: "URL Analysis",
      icon: <LinkIcon size={19} />,
    },
    {
      id: "email-analysis",
      label: "Email Analysis",
      icon: <Mail size={19} />,
    },
    {
      id: "history",
      label: "Investigation History",
      icon: <History size={19} />,
    },
    {
      id: "reports",
      label: "Reports",
      icon: <FileText size={19} />,
    },
  ];

  function getPageTitle() {
    const item = navItems.find((nav) => nav.id === activePage);

    if (item) return item.label;

    if (activePage === "details") return "Investigation Details";

    return "Dashboard";
  }

  function renderPage() {
    switch (activePage) {
      case "url-analysis":
        return (
          <URLAnalysisPage onResultSaved={loadHistory} />
        );

      case "email-analysis":
        return (
          <EmailAnalysisPage onResultSaved={loadHistory} />
        );

      case "history":
        return (
          <InvestigationHistoryPage
            history={history}
            loading={historyLoading}
            onRefresh={loadHistory}
            onNavigate={navigateTo}
          />
        );

      case "reports":
        return (
          <ReportsPage
            history={history}
            onNavigate={navigateTo}
          />
        );

      case "details":
        return (
          <InvestigationDetailsPage
            investigationId={selectedInvestigationId}
            onBack={() => navigateTo("history")}
          />
        );

      case "dashboard":
      default:
        return (
          <DashboardPage
            history={history}
            onNavigate={navigateTo}
            loading={historyLoading}
          />
        );
    }
  }

  return (
    <div className="app-shell">
      {sidebarOpen && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="sidebar-brand">
          <div className="brand-logo">
            <ShieldCheck size={27} />
          </div>

          <div className="brand-text">
            <h2>PhishGuard</h2>
            <span>PRO SECURITY</span>
          </div>

          <button
            className="sidebar-close icon-button"
            aria-label="Close menu"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-section-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${
                activePage === item.id ? "nav-item-active" : ""
              }`}
              onClick={() => navigateTo(item.id)}
            >
              {item.icon}
              <span>{item.label}</span>

              {activePage === item.id && (
                <span className="nav-active-indicator" />
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-spacer" />

        <div className="sidebar-security-card">
          <div className="sidebar-security-icon">
            <LockKeyhole size={20} />
          </div>

          <h4>Security Workspace</h4>

          <p>
            Investigate suspicious URLs and email content from one place.
          </p>

          <button onClick={() => navigateTo("url-analysis")}>
            Start analysis <ArrowRight size={15} />
          </button>
        </div>

        <div className="sidebar-footer">
          <div
            className={`connection-dot ${
              backendOnline ? "connection-online" : "connection-offline"
            }`}
          />

          <span>
            Backend {backendOnline ? "Connected" : "Disconnected"}
          </span>

          <button
            className="icon-button connection-refresh"
            title="Check backend connection"
            onClick={checkBackend}
          >
            <RefreshCw size={15} />
          </button>
        </div>
      </aside>

      <div className="main-layout">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu-button icon-button"
              aria-label="Open navigation"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu size={22} />
            </button>

            <div className="breadcrumb">
              <span>PhishGuard Pro</span>
              <ChevronRight size={15} />
              <strong>{getPageTitle()}</strong>
            </div>
          </div>

          <div className="topbar-right">
            <div className="topbar-status">
              <span
                className={`connection-dot ${
                  backendOnline
                    ? "connection-online"
                    : "connection-offline"
                }`}
              />

              {backendOnline ? "System Online" : "System Offline"}
            </div>

            <div className="topbar-avatar">
              <ShieldCheck size={19} />
            </div>
          </div>
        </header>

        <main className="main-content">
          {historyError && activePage === "dashboard" && (
            <div className="global-error">
              <AlertTriangle size={18} />

              <span>{historyError}</span>

              <button
                className="text-button"
                onClick={() => {
                  loadHistory();
                  checkBackend();
                }}
              >
                Retry
              </button>
            </div>
          )}

          {renderPage()}
        </main>

        <footer className="app-footer">
          <div className="footer-brand">
            <ShieldCheck size={17} />
            <span>PhishGuard Pro</span>
          </div>

          <p>
            Security analysis for educational and defensive purposes.
          </p>

          <span className="footer-version">Local Workspace</span>
        </footer>
      </div>
    </div>
  );
}

export default App;

