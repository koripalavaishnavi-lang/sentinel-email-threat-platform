import { useRef, useState } from "react";
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
} from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import "./App.css";

// Leaflet marker fix
delete L.Icon.Default.prototype._getIconUrl;

L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
});

const arr = (v) => (Array.isArray(v) ? v : []);

const esc = (v) =>
  String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

function App() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState("Dashboard");

  const uploadRef = useRef(null);

  // Settings
  const [settings, setSettings] = useState({
    threatIntel: true,
    geolocation: true,
    riskScoring: true,
  });

  const toggle = (key) =>
    setSettings((s) => ({
      ...s,
      [key]: !s[key],
    }));

  // Select .eml file
  const handleFile = (e) => {
    const selected = e.target.files?.[0];

    if (!selected) return;

    if (!selected.name.toLowerCase().endsWith(".eml")) {
      setError("Please select a valid .eml email file.");
      setFile(null);
      return;
    }

    setFile(selected);
    setError("");
  };

  // Analyze email
  const analyze = async () => {
    if (!file) {
      setError("Please select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");

    const form = new FormData();
    form.append("file", file);

    try {
      const response = await fetch(
        "https://sentinel-email-threat-backend.onrender.com/api/analyze-email",
        {
          method: "POST",
          body: form,
        }
      );

      if (!response.ok) {
        throw new Error(`Backend returned ${response.status}`);
      }

      const result = await response.json();

      if (!result.success) {
        throw new Error(
          result.message || "Email analysis failed."
        );
      }

      setData(result);
      setPage("Investigate");

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });
    } catch (err) {
      console.error(err);
      setError(
        "Unable to connect to the backend. Please make sure the backend is running."
      );
    } finally {
      setLoading(false);
    }
  };

  // Reset
  const reset = () => {
    setFile(null);
    setData(null);
    setError("");
    setPage("Dashboard");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  // Navigation
  const dashboard = () => {
    setPage("Dashboard");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const uploadPage = () => {
    setPage("Analyze Email");

    setTimeout(() => {
      uploadRef.current?.scrollIntoView({
        behavior: "smooth",
      });
    }, 50);
  };

  const investigate = () => {
    if (!data) {
      uploadPage();
      return;
    }

    setPage("Investigate");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const reports = () => {
    if (!data) {
      uploadPage();
      return;
    }

    setPage("Reports");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Data
  const email = data?.email || {};
  const forensic = data?.forensics || {};
  const auth = data?.authentication || {};
  const ti = data?.threat_intelligence || {};
  const risk = data?.risk || {};

  const urls = arr(forensic.urls);
  const domains = arr(forensic.domains);
  const ips = arr(forensic.ip_addresses);
  const received = arr(forensic.received_headers);

  const geo = arr(data?.geolocation);

  const tiIps = arr(ti.ips);
  const tiDomains = arr(ti.domains);
  const tiUrls = arr(ti.urls);

  const indicators = [
    ...tiIps,
    ...tiDomains,
    ...tiUrls,
  ];

  const summary = ti.summary || {};
  const riskScore = Number(risk.score || 0);
  const riskLevel = risk.level || "LOW";
  const reasons = arr(risk.reasons);

  const body =
    data?.body ||
    email.body ||
    "No email body available.";

  const riskClass = (level) => {
    const v = String(level).toLowerCase();

    if (v.includes("critical")) return "risk-critical";
    if (v.includes("high")) return "risk-high";
    if (v.includes("medium")) return "risk-medium";

    return "risk-low";
  };

  const scoreClass = (score) => {
    if (score >= 75) return "score-high";
    if (score >= 40) return "score-medium";
    return "score-low";
  };

  const formatDate = (value) => {
    if (!value) return "Not available";

    try {
      return new Date(value).toLocaleString();
    } catch {
      return value;
    }
  };

  // PDF report
  const generateReport = () => {
    if (!data) {
      setError("Analyze an email before generating a report.");
      return;
    }

    const win = window.open(
      "",
      "_blank",
      "width=1100,height=850"
    );

    if (!win) {
      setError("Please allow pop-ups to generate the report.");
      return;
    }

    const urlHtml =
      urls.length > 0
        ? urls.map((x) => `<li>${esc(x)}</li>`).join("")
        : "<li>None detected</li>";

    const domainHtml =
      domains.length > 0
        ? domains.map((x) => `<li>${esc(x)}</li>`).join("")
        : "<li>None detected</li>";

    const ipHtml =
      ips.length > 0
        ? ips.map((x) => `<li>${esc(x)}</li>`).join("")
        : "<li>None detected</li>";

    const headerHtml =
      received.length > 0
        ? received
            .map((x) => `<li>${esc(x)}</li>`)
            .join("")
        : "<li>None detected</li>";

    const reasonHtml =
      reasons.length > 0
        ? reasons.map((x) => `<li>${esc(x)}</li>`).join("")
        : "<li>No suspicious indicators detected.</li>";

    const threatHtml =
      indicators.length > 0
        ? indicators
            .map(
              (x) => `
                <tr>
                  <td>${esc(x.indicator || "Unknown")}</td>
                  <td>${esc(x.type || "Unknown")}</td>
                  <td>${esc(x.status || "UNKNOWN")}</td>
                  <td>${esc(x.source || "Unknown")}</td>
                  <td>${esc(x.confidence ?? 0)}%</td>
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
      geo.length > 0
        ? geo
            .map(
              (g) => `
                <tr>
                  <td>${esc(g.ip || "Unknown")}</td>
                  <td>${esc(g.country || "Unknown")}</td>
                  <td>${esc(g.region || "Unknown")}</td>
                  <td>${esc(g.city || "Unknown")}</td>
                  <td>${esc(g.organization || "Unknown")}</td>
                </tr>
              `
            )
            .join("")
        : `
            <tr>
              <td colspan="5">No public IP geolocation available.</td>
            </tr>
          `;

    win.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SENTINEL Security Analysis Report</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            padding: 40px;
            color: #172033;
            line-height: 1.5;
          }

          h1 {
            margin-bottom: 5px;
          }

          h2 {
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 8px;
          }

          .sub {
            color: #64748b;
          }

          .risk {
            margin: 25px 0;
            padding: 20px;
            border: 2px solid #ddd;
            border-radius: 10px;
          }

          .score {
            font-size: 40px;
            font-weight: bold;
          }

          .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
          }

          .item {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 12px;
          }

          .label {
            font-size: 11px;
            color: #64748b;
            font-weight: bold;
            text-transform: uppercase;
          }

          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
          }

          th,
          td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            word-break: break-word;
          }

          th {
            background: #f1f5f9;
          }

          pre {
            white-space: pre-wrap;
            background: #f8fafc;
            padding: 15px;
            border: 1px solid #ddd;
          }

          .footer {
            margin-top: 35px;
            color: #64748b;
            font-size: 11px;
          }

          @media print {
            .print-button {
              display: none;
            }
          }
        </style>
      </head>

      <body>
        <h1>SENTINEL</h1>

        <div class="sub">
          Email Threat Intelligence & Forensic Analysis
        </div>

        <div class="sub">
          Report generated: ${esc(
            new Date().toLocaleString()
          )}
        </div>

        <div class="risk">
          <div class="label">Threat Assessment</div>
          <div class="score">${esc(riskScore)} / 100</div>
          <strong>Risk Level: ${esc(riskLevel)}</strong>
        </div>

        <h2>Email Information</h2>

        <div class="grid">
          <div class="item">
            <div class="label">Filename</div>
            ${esc(email.filename || file?.name || "Unknown")}
          </div>

          <div class="item">
            <div class="label">Sender</div>
            ${esc(email.sender || "Not available")}
          </div>

          <div class="item">
            <div class="label">Recipient</div>
            ${esc(email.recipient || "Not available")}
          </div>

          <div class="item">
            <div class="label">Reply-To</div>
            ${esc(email.reply_to || "Not available")}
          </div>

          <div class="item">
            <div class="label">Date</div>
            ${esc(formatDate(email.date))}
          </div>

          <div class="item">
            <div class="label">Subject</div>
            ${esc(email.subject || "Not available")}
          </div>
        </div>

        <h2>Detection Reasons</h2>
        <ul>${reasonHtml}</ul>

        <h2>Threat Intelligence</h2>

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
            ${esc(auth.spf || "Not Found")}
          </div>

          <div class="item">
            <div class="label">DKIM</div>
            ${esc(auth.dkim || "Not Found")}
          </div>

          <div class="item">
            <div class="label">Authentication Results</div>
            ${esc(
              auth.authentication_results ||
                "Not available"
            )}
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

        <pre>${esc(body)}</pre>

        <div class="footer">
          SENTINEL Security Operations Platform<br />
          Automated forensic analysis report.
        </div>

        <button
          class="print-button"
          onclick="window.print()"
          style="
            margin-top:25px;
            padding:12px 20px;
            font-weight:bold;
            cursor:pointer;
          "
        >
          Print / Save as PDF
        </button>
      </body>
      </html>
    `);

    win.document.close();
    win.focus();

    setTimeout(() => {
      win.print();
    }, 500);
  };

  // Upload section
  const UploadSection = () => (
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

        {data && (
          <button
            className="secondary-button"
            onClick={reset}
          >
            New Analysis
          </button>
        )}
      </div>

      <div className="upload-box">
        <div className="upload-icon">✉</div>

        <h3>
          {file ? file.name : "Upload an email file"}
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
            onChange={handleFile}
            hidden
          />
        </label>

        {file && (
          <button
            className="analyze-button"
            onClick={analyze}
            disabled={loading}
          >
            {loading ? "Analyzing..." : "Analyze Email"}
          </button>
        )}
      </div>

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}
    </section>
  );

  // Results section
  const Results = () => {
    if (!data) {
      return (
        <section className="panel">
          <div className="empty-state">
            <h3>No Investigation Available</h3>
            <p>
              Upload and analyze an email to begin.
            </p>

            <button
              className="primary-button"
              onClick={uploadPage}
            >
              Analyze Email
            </button>
          </div>
        </section>
      );
    }

    return (
      <div>
        <div className="success-message">
          <span>✓</span>
          Email analyzed successfully
        </div>

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
                  file?.name ||
                  "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>Sender</span>
              <strong>
                {email.sender || "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>Recipient</span>
              <strong>
                {email.recipient || "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>Reply-To</span>
              <strong>
                {email.reply_to || "Not available"}
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
                {email.subject || "Not available"}
              </strong>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Threat Assessment</h3>
              <p>
                Automated forensic risk assessment.
              </p>
            </div>

            <div
              className={`risk-badge ${riskClass(
                riskLevel
              )}`}
            >
              {riskLevel}
            </div>
          </div>

          <div className="threat-layout">
            <div className="score-card">
              <div
                className={`risk-score ${scoreClass(
                  riskScore
                )}`}
              >
                {riskScore}
              </div>

              <span>Threat Score / 100</span>
            </div>

            <div className="risk-reasons">
              <h4>Detection Reasons</h4>

              {reasons.length ? (
                <ul>
                  {reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              ) : (
                <p>No suspicious indicators detected.</p>
              )}
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Investigation Summary</h3>
              <p>
                High-level findings from the investigation.
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
                {ips.length}
              </span>
              <strong>IP Addresses</strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {indicators.length}
              </span>
              <strong>Threat Indicators</strong>
            </div>
          </div>
        </section>

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
                {ips.length}
              </span>
              <strong>IP Addresses</strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {received.length}
              </span>
              <strong>Received Headers</strong>
            </div>
          </div>

          {urls.length > 0 && (
            <div className="indicator-section">
              <h4>Extracted URLs</h4>
              <div className="tag-list">
                {urls.map((x, i) => (
                  <span className="tag" key={i}>
                    {x}
                  </span>
                ))}
              </div>
            </div>
          )}

          {domains.length > 0 && (
            <div className="indicator-section">
              <h4>Extracted Domains</h4>
              <div className="tag-list">
                {domains.map((x, i) => (
                  <span className="tag" key={i}>
                    {x}
                  </span>
                ))}
              </div>
            </div>
          )}

          {ips.length > 0 && (
            <div className="indicator-section">
              <h4>IP Addresses</h4>
              <div className="tag-list">
                {ips.map((x, i) => (
                  <span className="tag ip-tag" key={i}>
                    {x}
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Email Authentication</h3>
              <p>
                SPF, DKIM and Authentication-Results.
              </p>
            </div>
          </div>

          <div className="auth-grid">
            <div className="auth-card">
              <span>SPF</span>
              <strong>
                {auth.spf || "Not Found"}
              </strong>
            </div>

            <div className="auth-card">
              <span>DKIM</span>
              <strong>
                {auth.dkim || "Not Found"}
              </strong>
            </div>

            <div className="auth-card">
              <span>Authentication Results</span>
              <strong>
                {auth.authentication_results ||
                  "Not available"}
              </strong>
            </div>
          </div>
        </section>

        {settings.threatIntel && (
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>Threat Intelligence</h3>
                <p>
                  External intelligence results.
                </p>
              </div>
            </div>

            <div className="indicator-grid">
              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.total_indicators ??
                    indicators.length}
                </span>
                <strong>Total</strong>
              </div>

              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.malicious || 0}
                </span>
                <strong>Malicious</strong>
              </div>

              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.suspicious || 0}
                </span>
                <strong>Suspicious</strong>
              </div>

              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.clean || 0}
                </span>
                <strong>Clean</strong>
              </div>
            </div>

            {indicators.length > 0 && (
              <div style={{ marginTop: 20 }}>
                {indicators.map((item, i) => (
                  <div
                    className="panel"
                    key={i}
                    style={{ marginBottom: 12 }}
                  >
                    <strong>
                      {item.indicator || "Unknown"}
                    </strong>

                    <p>
                      Type: {item.type || "Unknown"}
                      <br />
                      Status: {item.status || "Unknown"}
                      <br />
                      Source:{" "}
                      {item.source || "Threat Intelligence"}
                      <br />
                      Confidence:{" "}
                      {item.confidence ?? 0}%
                    </p>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {settings.geolocation && (
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>🌍 IP Geolocation</h3>
                <p>
                  Geographic intelligence from public IPs.
                </p>
              </div>
            </div>

            {geo.length > 0 ? (
              <div className="geo-grid">
                {geo.map((g, i) => (
                  <div className="geo-card" key={i}>
                    <div className="geo-card-header">
                      <div className="geo-globe">🌐</div>

                      <div>
                        <h4>{g.ip || "Unknown IP"}</h4>
                        <span>
                          {g.country || "Unknown"}
                        </span>
                      </div>
                    </div>

                    <div className="geo-details">
                      <div>
                        <span>Country</span>
                        <strong>
                          {g.country || "Unknown"}
                        </strong>
                      </div>

                      <div>
                        <span>Region</span>
                        <strong>
                          {g.region || "Unknown"}
                        </strong>
                      </div>

                      <div>
                        <span>City</span>
                        <strong>
                          {g.city || "Unknown"}
                        </strong>
                      </div>

                      <div>
                        <span>Organization</span>
                        <strong>
                          {g.organization || "Unknown"}
                        </strong>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p>No public IP geolocation available.</p>
            )}
          </section>
        )}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>🗺️ IP Geolocation Map</h3>
              <p>
                Visual representation of detected public IPs.
              </p>
            </div>
          </div>

          {geo.some(
            (g) =>
              g.latitude != null &&
              g.longitude != null
          ) ? (
            <MapContainer
              center={[
                Number(
                  geo.find(
                    (g) =>
                      g.latitude != null &&
                      g.longitude != null
                  ).latitude
                ),
                Number(
                  geo.find(
                    (g) =>
                      g.latitude != null &&
                      g.longitude != null
                  ).longitude
                ),
              ]}
              zoom={4}
              style={{
                height: "400px",
                width: "100%",
                borderRadius: "10px",
              }}
            >
              <TileLayer
                attribution="&copy; OpenStreetMap contributors"
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              />

              {geo.map((g, i) =>
                g.latitude != null &&
                g.longitude != null ? (
                  <Marker
                    key={i}
                    position={[
                      Number(g.latitude),
                      Number(g.longitude),
                    ]}
                  >
                    <Popup>
                      <strong>
                        IP: {g.ip || "Unknown"}
                      </strong>
                      <br />
                      Country:{" "}
                      {g.country || "Unknown"}
                      <br />
                      City: {g.city || "Unknown"}
                      <br />
                      Organization:{" "}
                      {g.organization || "Unknown"}
                    </Popup>
                  </Marker>
                ) : null
              )}
            </MapContainer>
          ) : (
            <p>No mappable public IP location.</p>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Email Body</h3>
              <p>Extracted message content.</p>
            </div>
          </div>

          <div
            className="email-body"
            style={{
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {body}
          </div>
        </section>

        <div className="investigation-actions">
          <button
            className="primary-button"
            onClick={generateReport}
          >
            📄 Generate Security Report
          </button>

          <button
            className="secondary-button"
            onClick={reset}
          >
            ↻ New Investigation
          </button>
        </div>
      </div>
    );
  };

  // Settings page
  const Settings = () => (
    <section className="panel" style={{ padding: 28 }}>
      <div className="panel-header">
        <div>
          <h3>Settings</h3>
          <p>
            Configure SENTINEL analysis preferences.
          </p>
        </div>
      </div>

      <div style={{ marginTop: 25 }}>
        <h4>Analysis Features</h4>

        {[
          [
            "threatIntel",
            "Threat Intelligence",
            "VirusTotal and AbuseIPDB intelligence.",
          ],
          [
            "geolocation",
            "IP Geolocation",
            "Display geographical information for public IPs.",
          ],
          [
            "riskScoring",
            "Automatic Risk Scoring",
            "Calculate email threat risk automatically.",
          ],
        ].map(([key, title, description]) => (
          <div
            key={key}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "18px",
              marginTop: "12px",
              border: "1px solid #dbe1ea",
              borderRadius: "10px",
            }}
          >
            <div>
              <strong>{title}</strong>
              <p style={{ margin: "5px 0 0", opacity: 0.7 }}>
                {description}
              </p>
            </div>

            <button
              className="secondary-button"
              onClick={() => toggle(key)}
            >
              {settings[key] ? "ON" : "OFF"}
            </button>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 30 }}>
        <h4>System Status</h4>

        <div className="indicator-grid">
          <div className="indicator-card">
            <strong>● Backend</strong>
            <span>Connected</span>
          </div>

          <div className="indicator-card">
            <strong>● Forensic Engine</strong>
            <span>Ready</span>
          </div>

          <div className="indicator-card">
            <strong>● Threat Intelligence</strong>
            <span>Ready</span>
          </div>

          <div className="indicator-card">
            <strong>● Geolocation</strong>
            <span>Ready</span>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 30 }}>
        <h4>About SENTINEL</h4>

        <p>
          SENTINEL is an Email Threat Intelligence &
          Forensic Analysis Platform designed to analyze
          suspicious email files and provide investigation
          insights.
        </p>

        <p style={{ opacity: 0.7 }}>
          Version 1.0 • Security Operations Platform
        </p>
      </div>
    </section>
  );

  // Reports page
  const Reports = () => (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>📄 Security Report</h3>
          <p>
            Generate a professional report for the
            current investigation.
          </p>
        </div>
      </div>

      {data ? (
        <div style={{ padding: 20 }}>
          <h4>Investigation Report Ready</h4>

          <p>
            Risk Level:{" "}
            <strong>{riskLevel}</strong>
          </p>

          <p>
            Risk Score:{" "}
            <strong>{riskScore} / 100</strong>
          </p>

          <p>
            Threat Indicators:{" "}
            <strong>{indicators.length}</strong>
          </p>

          <button
            className="primary-button"
            onClick={generateReport}
          >
            📄 Generate PDF / Print Report
          </button>
        </div>
      ) : (
        <div className="empty-state">
          <h3>No Report Available</h3>
          <p>
            Analyze an email first to generate a report.
          </p>

          <button
            className="primary-button"
            onClick={uploadPage}
          >
            Analyze Email
          </button>
        </div>
      )}
    </section>
  );

  // Main render
  return (
    <div className="app">

      {/* SIDEBAR */}
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
              page === "Dashboard" ? "active" : ""
            }`}
            onClick={dashboard}
          >
            <span>▦</span>
            Dashboard
          </button>

          <button
            className={`nav-item ${
              page === "Analyze Email"
                ? "active"
                : ""
            }`}
            onClick={uploadPage}
          >
            <span>✉</span>
            Analyze Email
          </button>

          <button
            className={`nav-item ${
              page === "Investigate"
                ? "active"
                : ""
            }`}
            onClick={investigate}
          >
            <span>⌕</span>
            Investigate
          </button>

          <button
            className={`nav-item ${
              page === "Reports"
                ? "active"
                : ""
            }`}
            onClick={reports}
          >
            <span>▤</span>
            Reports
          </button>

          <button
            className={`nav-item ${
              page === "Settings"
                ? "active"
                : ""
            }`}
            onClick={() => {
              setPage("Settings");
              window.scrollTo({
                top: 0,
                behavior: "smooth",
              });
            }}
          >
            <span>⚙</span>
            Settings
          </button>

        </nav>

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
              marginTop: 12,
              fontSize: 11,
              lineHeight: 1.7,
            }}
          >
            <div>● SENTINEL Engine Ready</div>
            <div>● Threat Intelligence Ready</div>
            <div>● Forensic Analyzer Ready</div>
          </div>

        </div>

      </aside>

      {/* MAIN */}
      <main className="main-content">

        <header className="topbar">

          <div>
            <h2>{page}</h2>

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

          {page === "Settings" && <Settings />}

          {page === "Reports" && <Reports />}

          {page === "Investigate" && <Results />}

          {(page === "Dashboard" ||
            page === "Analyze Email") && (
            <>
              <section className="stats-grid">

                <div className="stat-card">
                  <div className="stat-icon blue">
                    ✉
                  </div>

                  <div>
                    <span>Emails Analyzed</span>
                    <strong>
                      {data ? 1 : 0}
                    </strong>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-icon red">
                    ⚠
                  </div>

                  <div>
                    <span>Threats Detected</span>
                    <strong>
                      {summary.malicious || 0}
                    </strong>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-icon orange">
                    !
                  </div>

                  <div>
                    <span>High Risk</span>
                    <strong>
                      {["HIGH", "CRITICAL"].includes(
                        String(riskLevel).toUpperCase()
                      )
                        ? 1
                        : 0}
                    </strong>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-icon purple">
                    ⌕
                  </div>

                  <div>
                    <span>Investigations</span>
                    <strong>
                      {data ? 1 : 0}
                    </strong>
                  </div>
                </div>

              </section>

              <UploadSection />

              {data && <Results />}
            </>
          )}

        </div>

      </main>

    </div>
  );
}

export default App;