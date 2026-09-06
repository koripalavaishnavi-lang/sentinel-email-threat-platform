import { useRef, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import "./App.css";

// ============================================================
// LEAFLET MARKER FIX
// ============================================================

delete L.Icon.Default.prototype._getIconUrl;

L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
});

// ============================================================
// HELPER FUNCTIONS
// ============================================================

const escapeHtml = (value) => {
  if (value === null || value === undefined) return "";

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

const safeArray = (value) => {
  return Array.isArray(value) ? value : [];
};

// ============================================================
// APP
// ============================================================

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [emailData, setEmailData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activePage, setActivePage] = useState("Dashboard");

  const reportRef = useRef(null);
  const uploadRef = useRef(null);

  // ============================================================
  // FILE SELECTION
  // ============================================================

  const handleFileChange = (event) => {
    const file = event.target.files[0];

    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError("Please select a valid .eml email file.");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setError("");
  };

  // ============================================================
  // EMAIL ANALYSIS
  // ============================================================

  const analyzeEmail = async () => {
    if (!selectedFile) {
      setError("Please select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/analyze-email",
        {
          method: "POST",
          body: formData,
        }
      );

      if (!response.ok) {
        throw new Error(`Backend returned ${response.status}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || "Email analysis failed.");
      }

      setEmailData(data);
      setActivePage("Investigate");

      setTimeout(() => {
        window.scrollTo({
          top: 0,
          behavior: "smooth",
        });
      }, 100);
    } catch (err) {
      console.error(err);

      setError(
        "Unable to connect to the backend. Make sure FastAPI is running on port 8000."
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // RESET
  // ============================================================

  const resetAnalysis = () => {
    setSelectedFile(null);
    setEmailData(null);
    setError("");
    setActivePage("Dashboard");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  // ============================================================
  // NAVIGATION
  // ============================================================

  const goToUpload = () => {
    setActivePage("Analyze Email");

    setTimeout(() => {
      uploadRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 50);
  };

  const goToInvestigation = () => {
    setActivePage("Investigate");

    if (emailData) {
      setTimeout(() => {
        window.scrollTo({
          top: 0,
          behavior: "smooth",
        });
      }, 50);
    } else {
      goToUpload();
    }
  };

  const goToReports = () => {
    setActivePage("Reports");

    if (emailData) {
      setTimeout(() => {
        reportRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }, 50);
    } else {
      goToUpload();
    }
  };

  // ============================================================
  // RISK HELPERS
  // ============================================================

  const getRiskClass = (level) => {
    if (!level) return "risk-low";

    const value = String(level).toLowerCase();

    if (value.includes("critical")) return "risk-critical";
    if (value.includes("high")) return "risk-high";
    if (value.includes("medium")) return "risk-medium";

    return "risk-low";
  };

  const getRiskScoreClass = (score) => {
    if (score >= 75) return "score-high";
    if (score >= 40) return "score-medium";

    return "score-low";
  };

  const formatDate = (date) => {
    if (!date) return "Not available";

    try {
      return new Date(date).toLocaleString();
    } catch {
      return date;
    }
  };

  // ============================================================
  // DATA
  // ============================================================

  const email = emailData?.email || {};
  const forensics = emailData?.forensics || {};
  const authentication = emailData?.authentication || {};
  const threatIntel = emailData?.threat_intelligence || {};
  const risk = emailData?.risk || {};

  const urls = safeArray(forensics.urls);
  const domains = safeArray(forensics.domains);
  const ipAddresses = safeArray(forensics.ip_addresses);
  const receivedHeaders = safeArray(forensics.received_headers);

  const geoLocations = safeArray(emailData?.geolocation);

  const validGeoLocations = geoLocations.filter(
    (geo) =>
      geo &&
      geo.latitude !== null &&
      geo.latitude !== undefined &&
      geo.longitude !== null &&
      geo.longitude !== undefined
  );

  const firstLocation = validGeoLocations[0];

  const tiIps = safeArray(threatIntel.ips);
  const tiDomains = safeArray(threatIntel.domains);
  const tiUrls = safeArray(threatIntel.urls);

  const allThreatIndicators = [
    ...tiIps,
    ...tiDomains,
    ...tiUrls,
  ];

  const threatSummary = threatIntel.summary || {};

  const riskLevel = risk.level || "LOW";
  const riskScore = Number(risk.score || 0);
  const riskReasons = safeArray(risk.reasons);

  const emailBody =
    emailData?.body ||
    email.body ||
    "No email body available.";

  // ============================================================
  // THREAT INDICATOR RENDERER
  // ============================================================

  const renderThreatIndicator = (item, index) => {
    const status = item.status || "UNKNOWN";

    const statusClass =
      String(status).toLowerCase() === "malicious"
        ? "risk-high"
        : String(status).toLowerCase() === "suspicious"
        ? "risk-medium"
        : String(status).toLowerCase() === "clean"
        ? "risk-low"
        : "";

    return (
      <div className="threat-indicator-card" key={`${item.indicator}-${index}`}>
        <div className="threat-indicator-header">
          <strong>{item.indicator || "Unknown Indicator"}</strong>

          <span className={`risk-badge ${statusClass}`}>
            {status}
          </span>
        </div>

        <div className="threat-indicator-details">
          <div>
            <span>Type</span>
            <strong>{item.type || "Unknown"}</strong>
          </div>

          <div>
            <span>Source</span>
            <strong>{item.source || "Threat Intelligence"}</strong>
          </div>

          <div>
            <span>Confidence</span>
            <strong>{item.confidence ?? 0}%</strong>
          </div>

          <div>
            <span>Malicious</span>
            <strong>{item.malicious ?? 0}</strong>
          </div>

          <div>
            <span>Suspicious</span>
            <strong>{item.suspicious ?? 0}</strong>
          </div>

          <div>
            <span>Harmless</span>
            <strong>{item.harmless ?? 0}</strong>
          </div>

          <div>
            <span>Undetected</span>
            <strong>{item.undetected ?? 0}</strong>
          </div>

          {item.abuse_confidence_score !== undefined && (
            <div>
              <span>AbuseIPDB Confidence</span>
              <strong>
                {item.abuse_confidence_score}%
              </strong>
            </div>
          )}

          {item.total_reports !== undefined && (
            <div>
              <span>Reports</span>
              <strong>{item.total_reports}</strong>
            </div>
          )}
        </div>
      </div>
    );
  };

  // ============================================================
  // PDF REPORT
  // ============================================================

  const generateReport = () => {
    if (!emailData) {
      setError("Analyze an email before generating a report.");
      return;
    }

    const reportWindow = window.open(
      "",
      "_blank",
      "width=1100,height=850"
    );

    if (!reportWindow) {
      setError(
        "The report window was blocked. Please allow pop-ups for SENTINEL."
      );
      return;
    }

    const generatedAt = new Date().toLocaleString();

    const urlHtml =
      urls.length > 0
        ? urls
            .map(
              (url) =>
                `<li>${escapeHtml(url)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const domainHtml =
      domains.length > 0
        ? domains
            .map(
              (domain) =>
                `<li>${escapeHtml(domain)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const ipHtml =
      ipAddresses.length > 0
        ? ipAddresses
            .map(
              (ip) =>
                `<li>${escapeHtml(ip)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const headerHtml =
      receivedHeaders.length > 0
        ? receivedHeaders
            .map(
              (header) =>
                `<li>${escapeHtml(header)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const reasonHtml =
      riskReasons.length > 0
        ? riskReasons
            .map(
              (reason) =>
                `<li>${escapeHtml(reason)}</li>`
            )
            .join("")
        : "<li>No suspicious indicators detected.</li>";

    const threatHtml =
      allThreatIndicators.length > 0
        ? allThreatIndicators
            .map(
              (item) => `
                <tr>
                  <td>${escapeHtml(item.indicator || "Unknown")}</td>
                  <td>${escapeHtml(item.type || "Unknown")}</td>
                  <td>${escapeHtml(item.status || "UNKNOWN")}</td>
                  <td>${escapeHtml(item.source || "Unknown")}</td>
                  <td>${escapeHtml(item.confidence ?? 0)}%</td>
                </tr>
              `
            )
            .join("")
        : `
            <tr>
              <td colspan="5">No threat intelligence indicators found.</td>
            </tr>
          `;

    const geoHtml =
      geoLocations.length > 0
        ? geoLocations
            .map(
              (geo) => `
                <tr>
                  <td>${escapeHtml(geo.ip || "Unknown")}</td>
                  <td>${escapeHtml(geo.country || "Unknown")}</td>
                  <td>${escapeHtml(geo.region || "Unknown")}</td>
                  <td>${escapeHtml(geo.city || "Unknown")}</td>
                  <td>${escapeHtml(
                    geo.organization || "Unknown"
                  )}</td>
                </tr>
              `
            )
            .join("")
        : `
            <tr>
              <td colspan="5">No public IP geolocation available.</td>
            </tr>
          `;

    reportWindow.document.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>SENTINEL Security Analysis Report</title>

          <style>
            * {
              box-sizing: border-box;
            }

            body {
              font-family: Arial, Helvetica, sans-serif;
              margin: 0;
              padding: 40px;
              color: #172033;
              background: #ffffff;
              line-height: 1.5;
            }

            .header {
              border-bottom: 3px solid #172033;
              padding-bottom: 20px;
              margin-bottom: 30px;
            }

            .logo {
              font-size: 30px;
              font-weight: 800;
              letter-spacing: 2px;
            }

            .subtitle {
              color: #64748b;
              margin-top: 5px;
            }

            .report-date {
              font-size: 12px;
              color: #64748b;
              margin-top: 12px;
            }

            h2 {
              margin-top: 32px;
              border-bottom: 1px solid #dbe1ea;
              padding-bottom: 8px;
            }

            h3 {
              margin-top: 20px;
            }

            .risk-box {
              padding: 20px;
              border: 2px solid #dbe1ea;
              border-radius: 10px;
              margin: 20px 0;
            }

            .risk-score {
              font-size: 42px;
              font-weight: 800;
            }

            .risk-level {
              font-size: 18px;
              font-weight: 700;
            }

            .grid {
              display: grid;
              grid-template-columns: repeat(2, 1fr);
              gap: 12px;
            }

            .item {
              border: 1px solid #dbe1ea;
              border-radius: 8px;
              padding: 12px;
            }

            .label {
              font-size: 11px;
              text-transform: uppercase;
              color: #64748b;
              font-weight: 700;
            }

            .value {
              font-weight: 600;
              margin-top: 4px;
              word-break: break-word;
            }

            ul {
              padding-left: 20px;
            }

            table {
              width: 100%;
              border-collapse: collapse;
              margin-top: 12px;
              font-size: 13px;
            }

            th,
            td {
              border: 1px solid #dbe1ea;
              padding: 9px;
              text-align: left;
              vertical-align: top;
              word-break: break-word;
            }

            th {
              background: #f1f5f9;
            }

            pre {
              white-space: pre-wrap;
              word-wrap: break-word;
              background: #f8fafc;
              border: 1px solid #dbe1ea;
              border-radius: 8px;
              padding: 15px;
              font-family: Consolas, monospace;
              font-size: 12px;
            }

            .footer {
              margin-top: 40px;
              padding-top: 15px;
              border-top: 1px solid #dbe1ea;
              color: #64748b;
              font-size: 11px;
            }

            @media print {
              body {
                padding: 20px;
              }

              .no-print {
                display: none;
              }
            }
          </style>
        </head>

        <body>
          <div class="header">
            <div class="logo">SENTINEL</div>
            <div class="subtitle">
              Email Threat Intelligence & Forensic Analysis
            </div>
            <div class="report-date">
              Report generated: ${escapeHtml(generatedAt)}
            </div>
          </div>

          <div class="risk-box">
            <div class="label">Threat Assessment</div>
            <div class="risk-score">
              ${escapeHtml(riskScore)} / 100
            </div>
            <div class="risk-level">
              Risk Level: ${escapeHtml(riskLevel)}
            </div>
          </div>

          <h2>Email Information</h2>

          <div class="grid">
            <div class="item">
              <div class="label">Filename</div>
              <div class="value">
                ${escapeHtml(
                  email.filename ||
                    emailData.filename ||
                    selectedFile?.name ||
                    "Unknown"
                )}
              </div>
            </div>

            <div class="item">
              <div class="label">Sender</div>
              <div class="value">
                ${escapeHtml(email.sender || "Not available")}
              </div>
            </div>

            <div class="item">
              <div class="label">Recipient</div>
              <div class="value">
                ${escapeHtml(email.recipient || "Not available")}
              </div>
            </div>

            <div class="item">
              <div class="label">Reply-To</div>
              <div class="value">
                ${escapeHtml(email.reply_to || "Not available")}
              </div>
            </div>

            <div class="item">
              <div class="label">Date</div>
              <div class="value">
                ${escapeHtml(formatDate(email.date))}
              </div>
            </div>

            <div class="item">
              <div class="label">Subject</div>
              <div class="value">
                ${escapeHtml(email.subject || "Not available")}
              </div>
            </div>
          </div>

          <h2>Detection Reasons</h2>
          <ul>
            ${reasonHtml}
          </ul>

          <h2>Threat Intelligence Summary</h2>

          <div class="grid">
            <div class="item">
              <div class="label">Total Indicators</div>
              <div class="value">
                ${escapeHtml(threatSummary.total_indicators ?? 0)}
              </div>
            </div>

            <div class="item">
              <div class="label">Malicious</div>
              <div class="value">
                ${escapeHtml(threatSummary.malicious ?? 0)}
              </div>
            </div>

            <div class="item">
              <div class="label">Suspicious</div>
              <div class="value">
                ${escapeHtml(threatSummary.suspicious ?? 0)}
              </div>
            </div>

            <div class="item">
              <div class="label">Clean</div>
              <div class="value">
                ${escapeHtml(threatSummary.clean ?? 0)}
              </div>
            </div>
          </div>

          <table>
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Status</th>
                <th>Source</th>
                <th>Confidence</th>
              </tr>
            </thead>

            <tbody>
              ${threatHtml}
            </tbody>
          </table>

          <h2>Forensic Indicators</h2>

          <h3>URLs</h3>
          <ul>${urlHtml}</ul>

          <h3>Domains</h3>
          <ul>${domainHtml}</ul>

          <h3>IP Addresses</h3>
          <ul>${ipHtml}</ul>

          <h3>Received Headers</h3>
          <ul>${headerHtml}</ul>

          <h2>Email Authentication</h2>

          <div class="grid">
            <div class="item">
              <div class="label">SPF</div>
              <div class="value">
                ${escapeHtml(
                  authentication.spf || "Not Found"
                )}
              </div>
            </div>

            <div class="item">
              <div class="label">DKIM</div>
              <div class="value">
                ${escapeHtml(
                  authentication.dkim || "Not Found"
                )}
              </div>
            </div>

            <div class="item">
              <div class="label">Authentication Results</div>
              <div class="value">
                ${escapeHtml(
                  authentication.authentication_results ||
                    "Not available"
                )}
              </div>
            </div>
          </div>

          <h2>IP Geolocation</h2>

          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Country</th>
                <th>Region</th>
                <th>City</th>
                <th>Organization</th>
              </tr>
            </thead>

            <tbody>
              ${geoHtml}
            </tbody>
          </table>

          <h2>Email Body</h2>

          <pre>${escapeHtml(emailBody)}</pre>

          <div class="footer">
            SENTINEL Security Operations Platform<br />
            Automated forensic analysis report. Results should be
            reviewed by a qualified security analyst before taking
            defensive action.
          </div>

          <div class="no-print" style="
            margin-top:30px;
            text-align:center;
          ">
            <button
              onclick="window.print()"
              style="
                padding:12px 24px;
                font-size:15px;
                font-weight:700;
                cursor:pointer;
              "
            >
              Print / Save as PDF
            </button>
          </div>
        </body>
      </html>
    `);

    reportWindow.document.close();
    reportWindow.focus();

    setTimeout(() => {
      reportWindow.print();
    }, 500);
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="app">

      {/* ======================================================
          SIDEBAR
      ====================================================== */}

      <aside className="sidebar">

        <div className="brand">
          <div className="brand-icon">S</div>

          <div>
            <h1>SENTINEL</h1>
            <span>Threat Intelligence</span>
          </div>
        </div>

        <nav className="navigation">

          <button
            className={`nav-item ${
              activePage === "Dashboard" ? "active" : ""
            }`}
            onClick={() => {
              setActivePage("Dashboard");

              window.scrollTo({
                top: 0,
                behavior: "smooth",
              });
            }}
          >
            <span>▦</span>
            Dashboard
          </button>

          <button
            className={`nav-item ${
              activePage === "Analyze Email" ? "active" : ""
            }`}
            onClick={goToUpload}
          >
            <span>✉</span>
            Analyze Email
          </button>

          <button
            className={`nav-item ${
              activePage === "Investigate" ? "active" : ""
            }`}
            onClick={goToInvestigation}
          >
            <span>⌕</span>
            Investigate
          </button>

          <button
            className={`nav-item ${
              activePage === "Reports" ? "active" : ""
            }`}
            onClick={goToReports}
          >
            <span>▤</span>
            Reports
          </button>

          <button
            className={`nav-item ${
              activePage === "Settings" ? "active" : ""
            }`}
            onClick={() => setActivePage("Settings")}
          >
            <span>⚙</span>
            Settings
          </button>

        </nav>

        {/* SYSTEM STATUS */}

        <div className="sidebar-bottom">

          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>System Online</strong>
              <small>All services operational</small>
            </div>
          </div>

          <div
            style={{
              marginTop: "12px",
              fontSize: "11px",
              lineHeight: "1.7",
              opacity: 0.8,
            }}
          >
            <div>● SENTINEL Engine Ready</div>
            <div>● Threat Intelligence Ready</div>
            <div>● Forensic Analyzer Ready</div>
          </div>

        </div>

      </aside>

      {/* ======================================================
          MAIN CONTENT
      ====================================================== */}

      <main className="main-content">

        {/* HEADER */}

        <header className="topbar">

          <div>
            <h2>{activePage}</h2>

            <p>
              Email threat intelligence & forensic analysis
            </p>
          </div>

          <div className="analyst">

            <div className="analyst-avatar">
              A
            </div>

            <div>
              <strong>Analyst</strong>
              <span>Security Operations</span>
            </div>

          </div>

        </header>

        <div className="content">

          {/* ==================================================
              STATS
          ================================================== */}

          <section className="stats-grid">

            <div className="stat-card">
              <div className="stat-icon blue">✉</div>

              <div>
                <span>Emails Analyzed</span>
                <strong>
                  {emailData ? "1" : "0"}
                </strong>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon red">⚠</div>

              <div>
                <span>Threats Detected</span>

                <strong>
                  {(threatSummary.malicious || 0) > 0
                    ? threatSummary.malicious
                    : 0}
                </strong>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon orange">!</div>

              <div>
                <span>High Risk</span>

                <strong>
                  {["HIGH", "CRITICAL"].includes(
                    String(riskLevel).toUpperCase()
                  )
                    ? "1"
                    : "0"}
                </strong>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon purple">⌕</div>

              <div>
                <span>Investigations</span>

                <strong>
                  {emailData ? "1" : "0"}
                </strong>
              </div>
            </div>

          </section>

          {/* ==================================================
              UPLOAD
          ================================================== */}

          <section
            className="panel upload-panel"
            ref={uploadRef}
          >

            <div className="panel-header">

              <div>
                <h3>Analyze Email</h3>

                <p>
                  Upload an email file for forensic and
                  threat intelligence analysis.
                </p>
              </div>

              {emailData && (
                <button
                  className="secondary-button"
                  onClick={resetAnalysis}
                >
                  New Analysis
                </button>
              )}

            </div>

            <div className="upload-box">

              <div className="upload-icon">
                ✉
              </div>

              <h3>
                {selectedFile
                  ? selectedFile.name
                  : "Upload an email file"}
              </h3>

              <p>
                Select an <strong>.eml</strong> file to
                begin analysis.
              </p>

              <label className="file-button">

                Choose Email File

                <input
                  type="file"
                  accept=".eml,message/rfc822"
                  onChange={handleFileChange}
                  hidden
                />

              </label>

              {selectedFile && (
                <button
                  className="analyze-button"
                  onClick={analyzeEmail}
                  disabled={loading}
                >
                  {loading
                    ? "Analyzing..."
                    : "Analyze Email"}
                </button>
              )}

            </div>

            {error && (
              <div className="error-message">
                {error}
              </div>
            )}

          </section>

          {/* ==================================================
              RESULTS
          ================================================== */}

          {emailData && (
            <>

              {/* SUCCESS */}

              <div className="success-message">
                <span>✓</span>
                Email analyzed successfully
              </div>

              {/* =================================================
                  EMAIL INFORMATION
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Email Information</h3>

                    <p>
                      Basic metadata extracted from the email.
                    </p>
                  </div>

                </div>

                <div className="info-grid">

                  <div className="info-item">
                    <span>Filename</span>

                    <strong>
                      {email.filename ||
                        emailData.filename ||
                        selectedFile?.name ||
                        "Not available"}
                    </strong>
                  </div>

                  <div className="info-item">
                    <span>Sender</span>

                    <strong>
                      {email.sender ||
                        "Not available"}
                    </strong>
                  </div>

                  <div className="info-item">
                    <span>Recipient</span>

                    <strong>
                      {email.recipient ||
                        "Not available"}
                    </strong>
                  </div>

                  <div className="info-item">
                    <span>Reply-To</span>

                    <strong>
                      {email.reply_to ||
                        "Not available"}
                    </strong>
                  </div>

                  <div className="info-item">
                    <span>Date</span>

                    <strong>
                      {formatDate(email.date)}
                    </strong>
                  </div>

                  <div className="info-item">
                    <span>Subject</span>

                    <strong>
                      {email.subject ||
                        "Not available"}
                    </strong>
                  </div>

                </div>

              </section>

              {/* =================================================
                  THREAT ASSESSMENT
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Threat Assessment</h3>

                    <p>
                      Automated forensic risk assessment.
                    </p>
                  </div>

                  <div
                    className={`risk-badge ${getRiskClass(
                      riskLevel
                    )}`}
                  >
                    {riskLevel}
                  </div>

                </div>

                <div className="threat-layout">

                  <div className="score-card">

                    <div
                      className={`risk-score ${getRiskScoreClass(
                        riskScore
                      )}`}
                    >
                      {riskScore}
                    </div>

                    <span>
                      Threat Score / 100
                    </span>

                  </div>

                  <div className="risk-reasons">

                    <h4>Detection Reasons</h4>

                    {riskReasons.length > 0 ? (
                      <ul>
                        {riskReasons.map(
                          (reason, index) => (
                            <li key={index}>
                              {reason}
                            </li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>
                        No suspicious indicators detected.
                      </p>
                    )}

                  </div>

                </div>

              </section>

              {/* =================================================
                  INVESTIGATION SUMMARY
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Investigation Summary</h3>

                    <p>
                      High-level findings from the
                      current email investigation.
                    </p>
                  </div>

                </div>

                <div className="indicator-grid">

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {urls.length}
                    </span>

                    <strong>URLs</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {domains.length}
                    </span>

                    <strong>Domains</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {ipAddresses.length}
                    </span>

                    <strong>IP Addresses</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {allThreatIndicators.length}
                    </span>

                    <strong>Threat Indicators</strong>
                  </div>

                </div>

              </section>

              {/* =================================================
                  FORENSIC INDICATORS
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Forensic Indicators</h3>

                    <p>
                      Indicators extracted from the email.
                    </p>
                  </div>

                </div>

                <div className="indicator-grid">

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {urls.length}
                    </span>
                    <strong>URLs</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {domains.length}
                    </span>
                    <strong>Domains</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {ipAddresses.length}
                    </span>
                    <strong>IP Addresses</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {receivedHeaders.length}
                    </span>
                    <strong>Received Headers</strong>
                  </div>

                </div>

                {urls.length > 0 && (
                  <div className="indicator-section">

                    <h4>Extracted URLs</h4>

                    <div className="tag-list">

                      {urls.map((url, index) => (
                        <span
                          className="tag"
                          key={index}
                        >
                          {url}
                        </span>
                      ))}

                    </div>

                  </div>
                )}

                {domains.length > 0 && (
                  <div className="indicator-section">

                    <h4>Extracted Domains</h4>

                    <div className="tag-list">

                      {domains.map(
                        (domain, index) => (
                          <span
                            className="tag"
                            key={index}
                          >
                            {domain}
                          </span>
                        )
                      )}

                    </div>

                  </div>
                )}

                {ipAddresses.length > 0 && (
                  <div className="indicator-section">

                    <h4>IP Addresses</h4>

                    <div className="tag-list">

                      {ipAddresses.map(
                        (ip, index) => (
                          <span
                            className="tag ip-tag"
                            key={index}
                          >
                            {ip}
                          </span>
                        )
                      )}

                    </div>

                  </div>
                )}

                {receivedHeaders.length > 0 && (
                  <div className="indicator-section">

                    <h4>Received Headers</h4>

                    <div className="header-list">

                      {receivedHeaders.map(
                        (header, index) => (
                          <div
                            className="header-item"
                            key={index}
                          >
                            {header}
                          </div>
                        )
                      )}

                    </div>

                  </div>
                )}

                {urls.length === 0 &&
                  domains.length === 0 &&
                  ipAddresses.length === 0 &&
                  receivedHeaders.length === 0 && (
                    <div
                      style={{
                        padding: "20px 0",
                        opacity: 0.7,
                      }}
                    >
                      No forensic indicators were extracted.
                    </div>
                  )}

              </section>

              {/* =================================================
                  AUTHENTICATION
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Email Authentication</h3>

                    <p>
                      SPF, DKIM and Authentication-Results
                      information.
                    </p>
                  </div>

                </div>

                <div className="auth-grid">

                  <div className="auth-card">

                    <span>SPF</span>

                    <strong
                      className={
                        String(
                          authentication.spf || ""
                        )
                          .toLowerCase()
                          .includes("pass")
                          ? "auth-pass"
                          : "auth-fail"
                      }
                    >
                      {authentication.spf ||
                        "Not Found"}
                    </strong>

                  </div>

                  <div className="auth-card">

                    <span>DKIM</span>

                    <strong
                      className={
                        String(
                          authentication.dkim || ""
                        )
                          .toLowerCase()
                          .includes("pass")
                          ? "auth-pass"
                          : "auth-fail"
                      }
                    >
                      {authentication.dkim ||
                        "Not Found"}
                    </strong>

                  </div>

                  <div className="auth-card">

                    <span>
                      Authentication Results
                    </span>

                    <strong>
                      {authentication.authentication_results ||
                        "Not available"}
                    </strong>

                  </div>

                </div>

              </section>

              {/* =================================================
                  THREAT INTELLIGENCE
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Threat Intelligence</h3>

                    <p>
                      External intelligence results for
                      extracted indicators.
                    </p>
                  </div>

                </div>

                <div className="indicator-grid">

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {threatSummary.total_indicators ??
                        allThreatIndicators.length}
                    </span>
                    <strong>Total Indicators</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {threatSummary.malicious || 0}
                    </span>
                    <strong>Malicious</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {threatSummary.suspicious || 0}
                    </span>
                    <strong>Suspicious</strong>
                  </div>

                  <div className="indicator-card">
                    <span className="indicator-number">
                      {threatSummary.clean || 0}
                    </span>
                    <strong>Clean</strong>
                  </div>

                </div>

                {allThreatIndicators.length > 0 ? (
                  <div
                    style={{
                      display: "grid",
                      gap: "15px",
                      marginTop: "20px",
                    }}
                  >
                    {allThreatIndicators.map(
                      renderThreatIndicator
                    )}
                  </div>
                ) : (
                  <div
                    style={{
                      padding: "20px 0",
                      opacity: 0.7,
                    }}
                  >
                    No threat intelligence indicators
                    were returned.
                  </div>
                )}

              </section>

              {/* =================================================
                  GEOLOCATION
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>🌍 IP Geolocation</h3>

                    <p>
                      Geographic intelligence extracted
                      from public IP addresses.
                    </p>
                  </div>

                </div>

                {geoLocations.length > 0 ? (

                  <div className="geo-grid">

                    {geoLocations.map(
                      (geo, index) => (
                        <div
                          className="geo-card"
                          key={index}
                        >

                          <div className="geo-card-header">

                            <div className="geo-globe">
                              🌐
                            </div>

                            <div>
                              <h4>
                                {geo.ip ||
                                  "Unknown IP"}
                              </h4>

                              <span>
                                {geo.country_code ||
                                  "Location identified"}
                              </span>
                            </div>

                          </div>

                          <div className="geo-details">

                            <div>
                              <span>Country</span>
                              <strong>
                                {geo.country ||
                                  "Unknown"}
                              </strong>
                            </div>

                            <div>
                              <span>Region</span>
                              <strong>
                                {geo.region ||
                                  "Unknown"}
                              </strong>
                            </div>

                            <div>
                              <span>City</span>
                              <strong>
                                {geo.city ||
                                  "Unknown"}
                              </strong>
                            </div>

                            <div>
                              <span>Postal</span>
                              <strong>
                                {geo.postal ||
                                  "Unknown"}
                              </strong>
                            </div>

                            <div>
                              <span>Timezone</span>
                              <strong>
                                {geo.timezone ||
                                  "Unknown"}
                              </strong>
                            </div>

                            <div>
                              <span>ASN</span>
                              <strong>
                                {geo.asn ||
                                  "Unknown"}
                              </strong>
                            </div>

                          </div>

                          <div className="geo-organization">

                            <span>Organization</span>

                            <strong>
                              {geo.organization ||
                                "Unknown"}
                            </strong>

                          </div>

                          <div className="coordinates">

                            <span>Coordinates</span>

                            <strong>
                              {geo.latitude !== null &&
                              geo.latitude !== undefined &&
                              geo.longitude !== null &&
                              geo.longitude !== undefined
                                ? `${geo.latitude}, ${geo.longitude}`
                                : "Unavailable"}
                            </strong>

                          </div>

                        </div>
                      )
                    )}

                  </div>

                ) : (

                  <div
                    style={{
                      padding: "25px",
                      textAlign: "center",
                      border: "1px dashed #cbd5e1",
                      borderRadius: "10px",
                      opacity: 0.75,
                    }}
                  >
                    <strong>
                      No public IP addresses detected.
                    </strong>

                    <p>
                      Geolocation is available when the
                      email contains a globally routable
                      IP address.
                    </p>
                  </div>

                )}

              </section>

              {/* =================================================
                  MAP
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>🗺️ IP Geolocation Map</h3>

                    <p>
                      Visual representation of public IP
                      locations detected in the email.
                    </p>
                  </div>

                </div>

                {validGeoLocations.length > 0 &&
                firstLocation ? (

                  <div className="map-wrapper">

                    <MapContainer
                      center={[
                        Number(firstLocation.latitude),
                        Number(firstLocation.longitude),
                      ]}
                      zoom={4}
                      scrollWheelZoom={true}
                      className="leaflet-map"
                    >

                      <TileLayer
                        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                      />

                      {validGeoLocations.map(
                        (geo, index) => (
                          <Marker
                            key={index}
                            position={[
                              Number(geo.latitude),
                              Number(geo.longitude),
                            ]}
                          >

                            <Popup>

                              <div className="map-popup">

                                <strong>
                                  IP:{" "}
                                  {geo.ip ||
                                    "Unknown"}
                                </strong>

                                <span>
                                  Country:{" "}
                                  {geo.country ||
                                    "Unknown"}
                                </span>

                                <span>
                                  Region:{" "}
                                  {geo.region ||
                                    "Unknown"}
                                </span>

                                <span>
                                  City:{" "}
                                  {geo.city ||
                                    "Unknown"}
                                </span>

                                <span>
                                  Organization:{" "}
                                  {geo.organization ||
                                    "Unknown"}
                                </span>

                              </div>

                            </Popup>

                          </Marker>
                        )
                      )}

                    </MapContainer>

                  </div>

                ) : (

                  <div
                    style={{
                      minHeight: "250px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      textAlign: "center",
                      border: "1px dashed #cbd5e1",
                      borderRadius: "10px",
                      padding: "30px",
                      opacity: 0.75,
                    }}
                  >
                    <div>
                      <div
                        style={{
                          fontSize: "40px",
                          marginBottom: "10px",
                        }}
                      >
                        🗺️
                      </div>

                      <strong>
                        No mappable public IP location
                      </strong>

                      <p>
                        Upload an email containing a
                        public IP address to display
                        geolocation intelligence here.
                      </p>
                    </div>
                  </div>

                )}

              </section>

              {/* =================================================
                  EMAIL BODY
              ================================================= */}

              <section className="panel">

                <div className="panel-header">

                  <div>
                    <h3>Email Body</h3>

                    <p>
                      Extracted message content.
                    </p>
                  </div>

                </div>

                <div
                  className="email-body"
                  style={{
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {emailBody}
                </div>

              </section>

              {/* =================================================
                  REPORTS
              ================================================= */}

              <section
                className="panel"
                ref={reportRef}
              >

                <div className="panel-header">

                  <div>
                    <h3>📄 Security Report</h3>

                    <p>
                      Generate a professional investigation
                      report for this analysis.
                    </p>
                  </div>

                  <button
                    className="analyze-button"
                    onClick={generateReport}
                  >
                    Generate PDF Report
                  </button>

                </div>

                <div
                  style={{
                    padding: "20px",
                    borderRadius: "10px",
                    border: "1px solid #dbe1ea",
                    background: "#f8fafc",
                  }}
                >

                  <strong>
                    Report includes:
                  </strong>

                  <ul>
                    <li>Email metadata</li>
                    <li>Threat score and risk reasons</li>
                    <li>Threat intelligence indicators</li>
                    <li>Forensic indicators</li>
                    <li>SPF / DKIM authentication</li>
                    <li>IP geolocation</li>
                    <li>Original extracted email body</li>
                  </ul>

                  <p
                    style={{
                      marginBottom: 0,
                      opacity: 0.7,
                    }}
                  >
                    Clicking the button opens the browser
                    print dialog. Choose{" "}
                    <strong>Save as PDF</strong> to export
                    the report.
                  </p>

                </div>

              </section>

            </>
          )}

        </div>
      </main>
    </div>
  );
}

export default App;