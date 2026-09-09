import { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import "./App.css";

// ==================================================
// SENTINEL BACKEND
// ==================================================

const BACKEND_URL =
  "https://sentinel-email-threat-backend.onrender.com";

const API_URL =
  `${BACKEND_URL}/api/analyze-email`;

const GMAIL_STATUS_URL =
  `${BACKEND_URL}/api/gmail/status`;

const GMAIL_MESSAGES_URL =
  `${BACKEND_URL}/api/gmail/messages`;

const GMAIL_DISCONNECT_URL =
  `${BACKEND_URL}/api/gmail/disconnect`;

const GMAIL_AUTH_URL =
  `${BACKEND_URL}/api/auth/google`;

const GMAIL_ANALYZE_URL =
  `${BACKEND_URL}/api/gmail/analyze`;

// ==================================================
// LEAFLET MARKER FIX
// ==================================================

delete L.Icon.Default.prototype._getIconUrl;

L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
});

// ==================================================
// HELPERS
// ==================================================

const arr = (value) =>
  Array.isArray(value) ? value : [];

const esc = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

// ==================================================
// APP
// ==================================================

function App() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState("Dashboard");

  // =================================================
  // HISTORY
  // =================================================

  const [history, setHistory] = useState(() => {
    try {
      const saved =
        localStorage.getItem("sentinel_history");

      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const uploadRef = useRef(null);

  // =================================================
  // SETTINGS
  // =================================================

  const [settings, setSettings] = useState({
    threatIntel: true,
    geolocation: true,
    riskScoring: true,
  });

  const toggle = (key) => {
    setSettings((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };

  // =================================================
  // GMAIL STATE
  // =================================================

  const [gmailConnected, setGmailConnected] =
    useState(false);

  const [gmailEmail, setGmailEmail] =
    useState("");

  const [gmailMessages, setGmailMessages] =
    useState([]);

  const [gmailLoading, setGmailLoading] =
    useState(false);

  const [gmailError, setGmailError] =
    useState("");

  const [gmailPageToken, setGmailPageToken] =
    useState(null);

  const [gmailAnalyzingId, setGmailAnalyzingId] =
    useState("");

  // =================================================
  // SAVE HISTORY
  // =================================================

  useEffect(() => {
    try {
      localStorage.setItem(
        "sentinel_history",
        JSON.stringify(history)
      );
    } catch (err) {
      console.error(
        "Unable to save history:",
        err
      );
    }
  }, [history]);

  // =================================================
  // GMAIL STATUS
  // =================================================

  const checkGmailStatus = async () => {
    try {
      const response = await fetch(
        GMAIL_STATUS_URL
      );

      const result = await response.json();

      if (result?.connected) {
        setGmailConnected(true);
        setGmailEmail(
          result.email || ""
        );
      } else {
        setGmailConnected(false);
        setGmailEmail("");
      }
    } catch (err) {
      console.error(
        "Gmail status error:",
        err
      );

      setGmailConnected(false);
    }
  };

  useEffect(() => {
    checkGmailStatus();

    const params =
      new URLSearchParams(
        window.location.search
      );

    const gmailResult =
      params.get("gmail");

    if (gmailResult === "connected") {
      setPage("Gmail");
      setGmailError("");
      checkGmailStatus();

      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      );
    }

    if (gmailResult === "error") {
      setPage("Gmail");
      setGmailError(
        "Google Gmail authorization failed. Please try connecting again."
      );

      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      );
    }
  }, []);

  // =================================================
  // CONNECT GMAIL
  // =================================================

  const connectGmail = () => {
    setGmailError("");
    window.location.href =
      GMAIL_AUTH_URL;
  };

  // =================================================
  // DISCONNECT GMAIL
  // =================================================

  const disconnectGmail = async () => {
    try {
      setGmailLoading(true);
      setGmailError("");

      const response = await fetch(
        GMAIL_DISCONNECT_URL,
        {
          method: "POST",
        }
      );

      const result =
        await response.json();

      if (!result?.success) {
        throw new Error(
          result?.error ||
            "Unable to disconnect Gmail."
        );
      }

      setGmailConnected(false);
      setGmailEmail("");
      setGmailMessages([]);
      setGmailPageToken(null);
    } catch (err) {
      setGmailError(
        err?.message ||
          "Unable to disconnect Gmail."
      );
    } finally {
      setGmailLoading(false);
    }
  };

  // =================================================
  // LOAD GMAIL MESSAGES
  // =================================================

  const loadGmailMessages = async (
    pageToken = null
  ) => {
    try {
      setGmailLoading(true);
      setGmailError("");

      let url =
        `${GMAIL_MESSAGES_URL}?max_results=20`;

      if (pageToken) {
        url +=
          `&page_token=${encodeURIComponent(
            pageToken
          )}`;
      }

      const response =
        await fetch(url);

      const result =
        await response.json();

      if (!response.ok) {
        throw new Error(
          result?.error ||
            `Gmail returned ${response.status}.`
        );
      }

      if (!result?.success) {
        throw new Error(
          result?.error ||
            "Unable to load Gmail messages."
        );
      }

      if (pageToken) {
        setGmailMessages(
          (previous) => [
            ...previous,
            ...(result.messages || []),
          ]
        );
      } else {
        setGmailMessages(
          result.messages || []
        );
      }

      setGmailPageToken(
        result.next_page_token || null
      );
    } catch (err) {
      console.error(
        "Gmail messages error:",
        err
      );

      setGmailError(
        err?.message ||
          "Unable to load Gmail messages."
      );
    } finally {
      setGmailLoading(false);
    }
  };

  // =================================================
  // ANALYZE GMAIL MESSAGE
  // =================================================

  const analyzeGmailMessage = async (
    message
  ) => {
    if (!message?.id) {
      return;
    }

    try {
      setGmailAnalyzingId(
        message.id
      );
      setGmailError("");
      setError("");

      const response =
        await fetch(
          `${GMAIL_ANALYZE_URL}/${encodeURIComponent(
            message.id
          )}`
        );

      const result =
        await response.json();

      if (!response.ok) {
        throw new Error(
          result?.error ||
            result?.message ||
            `Gmail analysis returned ${response.status}.`
        );
      }

      if (!result?.success) {
        throw new Error(
          result?.error ||
            result?.message ||
            "Gmail email analysis failed."
        );
      }

      setData(result);
      setFile(null);

      // Add Gmail investigation to history.
      const historyItem = {
        id: Date.now(),

        analyzedAt:
          new Date().toISOString(),

        filename:
          result.email?.filename ||
          `gmail_${message.id}.eml`,

        sender:
          result.email?.sender ||
          message.sender ||
          "Unknown Sender",

        recipient:
          result.email?.recipient ||
          message.recipient ||
          "Unknown Recipient",

        subject:
          result.email?.subject ||
          message.subject ||
          "No Subject",

        riskScore:
          Number(
            result.risk?.score || 0
          ),

        riskLevel:
          result.risk?.level ||
          "LOW",

        malicious:
          Number(
            result
              .threat_intelligence
              ?.summary
              ?.malicious || 0
          ),

        suspicious:
          Number(
            result
              .threat_intelligence
              ?.summary
              ?.suspicious || 0
          ),

        totalIndicators:
          Number(
            result
              .threat_intelligence
              ?.summary
              ?.total_indicators || 0
          ),

        data: result,
      };

      setHistory((previous) => [
        historyItem,
        ...previous,
      ]);

      setPage("Investigate");

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });
    } catch (err) {
      console.error(
        "Gmail analysis error:",
        err
      );

      setGmailError(
        err?.message ||
          "Unable to analyze Gmail message."
      );
    } finally {
      setGmailAnalyzingId("");
    }
  };

  // =================================================
  // FILE SELECTION
  // =================================================

  const handleFile = (event) => {
    const selected =
      event.target.files?.[0];

    if (!selected) {
      return;
    }

    const fileName =
      selected.name.toLowerCase();

    const isEml =
      fileName.endsWith(".eml");

    const isPdf =
      fileName.endsWith(".pdf");

    if (!isEml && !isPdf) {
      setError(
        "Please select a valid .eml or .pdf email file."
      );

      setFile(null);
      return;
    }

    setFile(selected);
    setError("");
    setData(null);
  };

  // =================================================
  // ANALYZE EMAIL
  // =================================================

  const analyze = async () => {
    if (!file) {
      setError(
        "Please select an .eml or .pdf file first."
      );
      return;
    }

    setLoading(true);
    setError("");

    const form =
      new FormData();

    form.append(
      "file",
      file
    );

    try {
      const response =
        await fetch(
          API_URL,
          {
            method: "POST",
            body: form,
          }
        );

      const rawText =
        await response.text();

      let result = null;

      try {
        result = rawText
          ? JSON.parse(rawText)
          : null;
      } catch {
        throw new Error(
          `Backend returned an invalid response (${response.status}).`
        );
      }

      if (!response.ok) {
        throw new Error(
          result?.detail ||
            result?.message ||
            `Backend returned ${response.status}`
        );
      }

      if (!result?.success) {
        throw new Error(
          result?.message ||
            result?.error ||
            "Email analysis failed."
        );
      }

      setData(result);

      const historyItem = {
        id: Date.now(),

        analyzedAt:
          new Date().toISOString(),

        filename:
          result.email?.filename ||
          file.name ||
          "Unknown Email",

        sender:
          result.email?.sender ||
          "Unknown Sender",

        recipient:
          result.email?.recipient ||
          "Unknown Recipient",

        subject:
          result.email?.subject ||
          "No Subject",

        riskScore:
          Number(
            result.risk?.score || 0
          ),

        riskLevel:
          result.risk?.level ||
          "LOW",

        malicious:
          Number(
            result
              .threat_intelligence
              ?.summary
              ?.malicious || 0
          ),

        suspicious:
          Number(
            result
              .threat_intelligence
              ?.summary
              ?.suspicious || 0
          ),

        totalIndicators:
          Number(
            result
              .threat_intelligence
              ?.summary
              ?.total_indicators || 0
          ),

        data: result,
      };

      setHistory((previous) => [
        historyItem,
        ...previous,
      ]);

      setPage("Investigate");

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });
    } catch (err) {
      console.error(
        "SENTINEL analysis error:",
        err
      );

      setError(
        err?.message ||
          "Unable to connect to the backend."
      );
    } finally {
      setLoading(false);
    }
  };

  // =================================================
  // RESET
  // =================================================

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

  // =================================================
  // NAVIGATION
  // =================================================

  const dashboard = () => {
    setPage("Dashboard");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
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

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const reports = () => {
    if (!data) {
      uploadPage();
      return;
    }

    setPage("Reports");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const openHistoryItem = (
    item
  ) => {
    if (!item?.data) {
      return;
    }

    setData(item.data);
    setFile(null);
    setError("");
    setPage("Investigate");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const clearHistory = () => {
    if (
      window.confirm(
        "Are you sure you want to clear all investigation history?"
      )
    ) {
      setHistory([]);
      localStorage.removeItem(
        "sentinel_history"
      );
    }
  };

  // =================================================
  // CURRENT DATA
  // =================================================

  const email =
    data?.email || {};

  const forensic =
    data?.forensics || {};

  const auth =
    data?.authentication || {};

  const ti =
    data?.threat_intelligence || {};

  const risk =
    data?.risk || {};

  const urls =
    arr(forensic.urls);

  const domains =
    arr(forensic.domains);

  const ips =
    arr(forensic.ip_addresses);

  const received =
    arr(forensic.received_headers);

  const geo =
    arr(data?.geolocation);

  const tiIps =
    arr(ti.ips);

  const tiDomains =
    arr(ti.domains);

  const tiUrls =
    arr(ti.urls);

  const indicators = [
    ...tiIps,
    ...tiDomains,
    ...tiUrls,
  ];

  const summary =
    ti.summary || {};

  const riskScore =
    Number(risk.score || 0);

  const riskLevel =
    risk.level || "LOW";

  const reasons =
    arr(risk.reasons);

  const body =
    data?.body ||
    email.body ||
    "No email body available.";

  // =================================================
  // RISK CLASSES
  // =================================================

  const riskClass = (
    level
  ) => {
    const value =
      String(level).toLowerCase();

    if (
      value.includes("critical")
    ) {
      return "risk-critical";
    }

    if (
      value.includes("high")
    ) {
      return "risk-high";
    }

    if (
      value.includes("medium")
    ) {
      return "risk-medium";
    }

    return "risk-low";
  };

  const scoreClass = (
    score
  ) => {
    if (score >= 75) {
      return "score-high";
    }

    if (score >= 40) {
      return "score-medium";
    }

    return "score-low";
  };

  // =================================================
  // DATE FORMAT
  // =================================================

  const formatDate = (
    value
  ) => {
    if (!value) {
      return "Not available";
    }

    try {
      return new Date(
        value
      ).toLocaleString();
    } catch {
      return value;
    }
  };

  // =================================================
  // DASHBOARD STATS
  // =================================================

  const totalEmails =
    history.length;

  const totalThreats =
    history.reduce(
      (total, item) =>
        total +
        Number(
          item.malicious || 0
        ),
      0
    );

  const highRiskCount =
    history.filter(
      (item) =>
        ["HIGH", "CRITICAL"].includes(
          String(
            item.riskLevel || ""
          ).toUpperCase()
        )
    ).length;

  const totalInvestigations =
    history.length;

  const lowRiskCount =
    history.filter(
      (item) =>
        String(
          item.riskLevel || ""
        ).toUpperCase() === "LOW"
    ).length;

  const mediumRiskCount =
    history.filter(
      (item) =>
        String(
          item.riskLevel || ""
        ).toUpperCase() ===
        "MEDIUM"
    ).length;

  const criticalRiskCount =
    history.filter(
      (item) =>
        String(
          item.riskLevel || ""
        ).toUpperCase() ===
        "CRITICAL"
    ).length;

  // =================================================
  // SECURITY REPORT
  // =================================================

  const generateReport = () => {
    if (!data) {
      setError(
        "Analyze an email before generating a report."
      );
      return;
    }

    const win =
      window.open(
        "",
        "_blank",
        "width=1100,height=850"
      );

    if (!win) {
      setError(
        "Please allow pop-ups to generate the report."
      );
      return;
    }

    const urlHtml =
      urls.length > 0
        ? urls
            .map(
              (item) =>
                `<li>${esc(item)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const domainHtml =
      domains.length > 0
        ? domains
            .map(
              (item) =>
                `<li>${esc(item)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const ipHtml =
      ips.length > 0
        ? ips
            .map(
              (item) =>
                `<li>${esc(item)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const headerHtml =
      received.length > 0
        ? received
            .map(
              (item) =>
                `<li>${esc(item)}</li>`
            )
            .join("")
        : "<li>None detected</li>";

    const reasonHtml =
      reasons.length > 0
        ? reasons
            .map(
              (item) =>
                `<li>${esc(item)}</li>`
            )
            .join("")
        : "<li>No suspicious indicators detected.</li>";

    const threatHtml =
      indicators.length > 0
        ? indicators
            .map(
              (item) => `
                <tr>
                  <td>${esc(
                    item.indicator ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.type ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.status ||
                      "UNKNOWN"
                  )}</td>
                  <td>${esc(
                    item.source ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.confidence ?? 0
                  )}%</td>
                </tr>
              `
            )
            .join("")
        : `
            <tr>
              <td colspan="5">
                No threat intelligence indicators found.
              </td>
            </tr>
          `;

    const geoHtml =
      geo.length > 0
        ? geo
            .map(
              (item) => `
                <tr>
                  <td>${esc(
                    item.ip ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.country ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.region ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.city ||
                      "Unknown"
                  )}</td>
                  <td>${esc(
                    item.organization ||
                      "Unknown"
                  )}</td>
                </tr>
              `
            )
            .join("")
        : `
            <tr>
              <td colspan="5">
                No public IP geolocation available.
              </td>
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
            Report generated:
            ${esc(
              new Date().toLocaleString()
            )}
          </div>

          <div class="risk">
            <div class="label">
              Threat Assessment
            </div>

            <div class="score">
              ${esc(riskScore)} / 100
            </div>

            <strong>
              Risk Level:
              ${esc(riskLevel)}
            </strong>
          </div>

          <h2>Email Information</h2>

          <div class="grid">
            <div class="item">
              <div class="label">Filename</div>
              ${esc(
                email.filename ||
                  file?.name ||
                  "Unknown"
              )}
            </div>

            <div class="item">
              <div class="label">Sender</div>
              ${esc(
                email.sender ||
                  "Not available"
              )}
            </div>

            <div class="item">
              <div class="label">Recipient</div>
              ${esc(
                email.recipient ||
                  "Not available"
              )}
            </div>

            <div class="item">
              <div class="label">Reply-To</div>
              ${esc(
                email.reply_to ||
                  "Not available"
              )}
            </div>

            <div class="item">
              <div class="label">Date</div>
              ${esc(
                formatDate(
                  email.date
                )
              )}
            </div>

            <div class="item">
              <div class="label">Subject</div>
              ${esc(
                email.subject ||
                  "Not available"
              )}
            </div>
          </div>

          <h2>Detection Reasons</h2>

          <ul>
            ${reasonHtml}
          </ul>

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
              ${esc(
                auth.spf ||
                  "Not Found"
              )}
            </div>

            <div class="item">
              <div class="label">DKIM</div>
              ${esc(
                auth.dkim ||
                  "Not Found"
              )}
            </div>

            <div class="item">
              <div class="label">
                Authentication Results
              </div>
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
            SENTINEL Security Operations Platform
            <br />
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

  // =================================================
  // UPLOAD SECTION
  // =================================================

  const UploadSection = () => (
    <section
      className="panel upload-panel"
      ref={uploadRef}
    >
      <div className="panel-header">
        <div>
          <h3>Analyze Email</h3>

          <p>
            Upload an email file for forensic
            and threat intelligence analysis.
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
        <div className="upload-icon">
          ✉
        </div>

        <h3>
          {file
            ? file.name
            : "Upload an email file"}
        </h3>

        <p>
          Select an{" "}
          <strong>.eml</strong>{" "}
          or{" "}
          <strong>.pdf</strong>{" "}
          file to begin analysis.
        </p>

        <label className="file-button">
          Choose Email File

          <input
            type="file"
            accept=".eml,.pdf,message/rfc822,application/pdf"
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
  );

  // =================================================
  // GMAIL PAGE
  // =================================================

  const Gmail = () => (
    <div>
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>📧 Gmail Integration</h3>

            <p>
              Connect Gmail and analyze messages
              directly with the SENTINEL forensic engine.
            </p>
          </div>

          {gmailConnected && (
            <div
              className="risk-badge risk-low"
              style={{
                whiteSpace: "nowrap",
              }}
            >
              CONNECTED
            </div>
          )}
        </div>

        {!gmailConnected ? (
          <div
            className="empty-state"
            style={{
              padding: "40px 20px",
            }}
          >
            <div
              style={{
                fontSize: 48,
                marginBottom: 15,
              }}
            >
              📬
            </div>

            <h3>
              Connect Your Gmail Account
            </h3>

            <p>
              SENTINEL will use Gmail read-only
              access to retrieve email messages
              for security investigation.
            </p>

            <p
              style={{
                fontSize: 13,
                opacity: 0.7,
                maxWidth: 600,
                margin: "10px auto 20px",
              }}
            >
              SENTINEL does not send, delete, or
              modify your Gmail messages.
            </p>

            <button
              className="primary-button"
              onClick={connectGmail}
            >
              🔐 Connect Gmail
            </button>
          </div>
        ) : (
          <div>
            <div
              style={{
                padding: 20,
                marginTop: 20,
                border: "1px solid #dbe1ea",
                borderRadius: 10,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 15,
                flexWrap: "wrap",
              }}
            >
              <div>
                <span
                  style={{
                    display: "block",
                    fontSize: 12,
                    opacity: 0.65,
                    marginBottom: 5,
                  }}
                >
                  Connected Gmail Account
                </span>

                <strong>
                  {gmailEmail ||
                    "Gmail account connected"}
                </strong>
              </div>

              <div
                style={{
                  display: "flex",
                  gap: 10,
                  flexWrap: "wrap",
                }}
              >
                <button
                  className="primary-button"
                  onClick={() =>
                    loadGmailMessages()
                  }
                  disabled={gmailLoading}
                >
                  {gmailLoading
                    ? "Loading..."
                    : "↻ Load Gmail"}
                </button>

                <button
                  className="secondary-button"
                  onClick={
                    disconnectGmail
                  }
                  disabled={gmailLoading}
                >
                  Disconnect
                </button>
              </div>
            </div>

            {gmailMessages.length === 0 ? (
              <div
                className="empty-state"
                style={{
                  marginTop: 20,
                }}
              >
                <h3>
                  Gmail Inbox Ready
                </h3>

                <p>
                  Click "Load Gmail" to retrieve
                  recent messages.
                </p>

                <button
                  className="primary-button"
                  onClick={() =>
                    loadGmailMessages()
                  }
                  disabled={gmailLoading}
                >
                  📥 Load Gmail Messages
                </button>
              </div>
            ) : (
              <div
                style={{
                  marginTop: 20,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent:
                      "space-between",
                    alignItems: "center",
                    marginBottom: 15,
                    gap: 10,
                    flexWrap: "wrap",
                  }}
                >
                  <div>
                    <h4
                      style={{
                        margin: 0,
                      }}
                    >
                      Recent Gmail Messages
                    </h4>

                    <p
                      style={{
                        margin:
                          "5px 0 0",
                        opacity: 0.65,
                      }}
                    >
                      Select a message to run
                      SENTINEL analysis.
                    </p>
                  </div>

                  <span
                    style={{
                      fontSize: 13,
                      opacity: 0.65,
                    }}
                  >
                    {gmailMessages.length}{" "}
                    messages loaded
                  </span>
                </div>

                {gmailMessages.map(
                  (message) => (
                    <div
                      key={message.id}
                      className="panel"
                      style={{
                        marginBottom: 12,
                        padding: 18,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent:
                            "space-between",
                          alignItems:
                            "center",
                          gap: 20,
                          flexWrap: "wrap",
                        }}
                      >
                        <div
                          style={{
                            flex: 1,
                            minWidth: 250,
                          }}
                        >
                          <h4
                            style={{
                              margin:
                                "0 0 8px",
                              wordBreak:
                                "break-word",
                            }}
                          >
                            {message.subject ||
                              "No Subject"}
                          </h4>

                          <div
                            style={{
                              fontSize: 13,
                              marginBottom: 5,
                            }}
                          >
                            <strong>
                              From:
                            </strong>{" "}
                            {message.sender ||
                              "Unknown"}
                          </div>

                          <div
                            style={{
                              fontSize: 13,
                              marginBottom: 5,
                            }}
                          >
                            <strong>
                              To:
                            </strong>{" "}
                            {message.recipient ||
                              "Unknown"}
                          </div>

                          <div
                            style={{
                              fontSize: 12,
                              opacity: 0.65,
                              marginBottom: 8,
                            }}
                          >
                            {formatDate(
                              message.date
                            )}
                          </div>

                          {message.snippet && (
                            <p
                              style={{
                                margin:
                                  "8px 0 0",
                                fontSize: 13,
                                opacity: 0.7,
                                lineHeight: 1.5,
                              }}
                            >
                              {message.snippet}
                            </p>
                          )}
                        </div>

                        <button
                          className="primary-button"
                          onClick={() =>
                            analyzeGmailMessage(
                              message
                            )
                          }
                          disabled={
                            gmailAnalyzingId ===
                            message.id
                          }
                        >
                          {gmailAnalyzingId ===
                          message.id
                            ? "Analyzing..."
                            : "🔍 Analyze"}
                        </button>
                      </div>
                    </div>
                  )
                )}

                {gmailPageToken && (
                  <div
                    style={{
                      textAlign: "center",
                      marginTop: 20,
                    }}
                  >
                    <button
                      className="secondary-button"
                      onClick={() =>
                        loadGmailMessages(
                          gmailPageToken
                        )
                      }
                      disabled={
                        gmailLoading
                      }
                    >
                      {gmailLoading
                        ? "Loading..."
                        : "Load More Messages"}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {gmailError && (
          <div
            className="error-message"
            style={{
              marginTop: 15,
            }}
          >
            {gmailError}
          </div>
        )}
      </section>
    </div>
  );

  // =================================================
  // DASHBOARD
  // =================================================

  const Dashboard = () => (
    <div>
      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon blue">
            ✉
          </div>

          <div>
            <span>
              Emails Analyzed
            </span>

            <strong>
              {totalEmails}
            </strong>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon red">
            ⚠
          </div>

          <div>
            <span>
              Threats Detected
            </span>

            <strong>
              {totalThreats}
            </strong>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon orange">
            !
          </div>

          <div>
            <span>
              High Risk
            </span>

            <strong>
              {highRiskCount}
            </strong>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon purple">
            ⌕
          </div>

          <div>
            <span>
              Investigations
            </span>

            <strong>
              {totalInvestigations}
            </strong>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>
              Security Operations Overview
            </h3>

            <p>
              Current investigation activity
              and threat posture.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
            }}
          >
            <button
              className="secondary-button"
              onClick={() =>
                setPage("Gmail")
              }
            >
              📧 Gmail
            </button>

            <button
              className="primary-button"
              onClick={uploadPage}
            >
              + Analyze Email
            </button>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="empty-state">
            <h3>
              No Investigations Yet
            </h3>

            <p>
              Upload an .eml or .pdf file,
              or connect Gmail to begin
              your first SENTINEL investigation.
            </p>

            <div
              style={{
                display: "flex",
                justifyContent:
                  "center",
                gap: 10,
                flexWrap: "wrap",
              }}
            >
              <button
                className="primary-button"
                onClick={uploadPage}
              >
                Analyze Email
              </button>

              <button
                className="secondary-button"
                onClick={() =>
                  setPage("Gmail")
                }
              >
                Connect Gmail
              </button>
            </div>
          </div>
        ) : (
          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 15,
              marginTop: 20,
            }}
          >
            <div className="indicator-card">
              <span className="indicator-number">
                {lowRiskCount}
              </span>

              <strong>
                Low Risk
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {mediumRiskCount}
              </span>

              <strong>
                Medium Risk
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {highRiskCount}
              </span>

              <strong>
                High Risk
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {criticalRiskCount}
              </span>

              <strong>
                Critical
              </strong>
            </div>
          </div>
        )}
      </section>

      {history.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Recent Investigations
              </h3>

              <p>
                Latest email security
                investigations.
              </p>
            </div>

            <button
              className="secondary-button"
              onClick={() =>
                setPage("History")
              }
            >
              View All
            </button>
          </div>

          <div
            style={{
              marginTop: 15,
            }}
          >
            {history
              .slice(0, 5)
              .map((item) => (
                <div
                  key={item.id}
                  style={{
                    display: "flex",
                    justifyContent:
                      "space-between",
                    alignItems: "center",
                    gap: 15,
                    padding: "15px 0",
                    borderBottom:
                      "1px solid #e5e7eb",
                    flexWrap: "wrap",
                  }}
                >
                  <div
                    style={{
                      minWidth: 0,
                      flex: 1,
                    }}
                  >
                    <strong
                      style={{
                        display: "block",
                        overflow: "hidden",
                        textOverflow:
                          "ellipsis",
                        whiteSpace:
                          "nowrap",
                      }}
                    >
                      {item.subject ||
                        item.filename}
                    </strong>

                    <small>
                      {item.sender}
                    </small>

                    <div
                      style={{
                        fontSize: 12,
                        opacity: 0.65,
                        marginTop: 4,
                      }}
                    >
                      {formatDate(
                        item.analyzedAt
                      )}
                    </div>
                  </div>

                  <div
                    style={{
                      textAlign: "right",
                      flexShrink: 0,
                    }}
                  >
                    <div
                      className={`risk-badge ${riskClass(
                        item.riskLevel
                      )}`}
                    >
                      {item.riskLevel}
                    </div>

                    <strong
                      style={{
                        display: "block",
                        marginTop: 5,
                      }}
                    >
                      {item.riskScore}/100
                    </strong>
                  </div>

                  <button
                    className="secondary-button"
                    onClick={() =>
                      openHistoryItem(
                        item
                      )
                    }
                  >
                    Open
                  </button>
                </div>
              ))}
          </div>
        </section>
      )}
    </div>
  );

  // =================================================
  // HISTORY
  // =================================================

  const History = () => (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>
            Investigation History
          </h3>

          <p>
            Review previously analyzed
            emails stored in this browser.
          </p>
        </div>

        {history.length > 0 && (
          <button
            className="secondary-button"
            onClick={clearHistory}
          >
            Clear History
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <div className="empty-state">
          <h3>
            No Investigation History
          </h3>

          <p>
            Completed email investigations
            will appear here.
          </p>

          <button
            className="primary-button"
            onClick={uploadPage}
          >
            Analyze Email
          </button>
        </div>
      ) : (
        <div
          style={{
            marginTop: 20,
          }}
        >
          {history.map((item) => (
            <div
              key={item.id}
              className="panel"
              style={{
                marginBottom: 15,
                padding: 20,
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent:
                    "space-between",
                  alignItems: "center",
                  gap: 20,
                  flexWrap: "wrap",
                }}
              >
                <div>
                  <h4
                    style={{
                      margin: "0 0 6px",
                    }}
                  >
                    {item.subject ||
                      "No Subject"}
                  </h4>

                  <p
                    style={{
                      margin: "4px 0",
                    }}
                  >
                    <strong>
                      File:
                    </strong>{" "}
                    {item.filename}
                  </p>

                  <p
                    style={{
                      margin: "4px 0",
                    }}
                  >
                    <strong>
                      Sender:
                    </strong>{" "}
                    {item.sender}
                  </p>

                  <p
                    style={{
                      margin: "4px 0",
                    }}
                  >
                    <strong>
                      Analyzed:
                    </strong>{" "}
                    {formatDate(
                      item.analyzedAt
                    )}
                  </p>
                </div>

                <div
                  style={{
                    textAlign: "center",
                  }}
                >
                  <div
                    className={`risk-badge ${riskClass(
                      item.riskLevel
                    )}`}
                  >
                    {item.riskLevel}
                  </div>

                  <div
                    style={{
                      fontSize: 24,
                      fontWeight: 700,
                      marginTop: 8,
                    }}
                  >
                    {item.riskScore}/100
                  </div>

                  <small>
                    {item.malicious || 0}{" "}
                    malicious indicators
                  </small>
                </div>

                <button
                  className="primary-button"
                  onClick={() =>
                    openHistoryItem(
                      item
                    )
                  }
                >
                  Open Investigation
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );

  // =================================================
  // RESULTS
  // =================================================

  const Results = () => {
    if (!data) {
      return (
        <section className="panel">
          <div className="empty-state">
            <h3>
              No Investigation Available
            </h3>

            <p>
              Upload and analyze an email
              to begin.
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

        {/* EMAIL INFORMATION */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Email Information
              </h3>

              <p>
                Basic metadata extracted
                from the email.
              </p>
            </div>

            {data.source_type ===
              "GMAIL" && (
              <div
                className="risk-badge risk-low"
              >
                GMAIL
              </div>
            )}
          </div>

          <div className="info-grid">
            <div className="info-item">
              <span>
                Filename
              </span>

              <strong>
                {email.filename ||
                  file?.name ||
                  "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>
                Sender
              </span>

              <strong>
                {email.sender ||
                  "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>
                Recipient
              </span>

              <strong>
                {email.recipient ||
                  "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>
                Reply-To
              </span>

              <strong>
                {email.reply_to ||
                  "Not available"}
              </strong>
            </div>

            <div className="info-item">
              <span>
                Date
              </span>

              <strong>
                {formatDate(
                  email.date
                )}
              </strong>
            </div>

            <div className="info-item">
              <span>
                Subject
              </span>

              <strong>
                {email.subject ||
                  "Not available"}
              </strong>
            </div>
          </div>

          {email.gmail_message_id && (
            <div
              style={{
                marginTop: 15,
                fontSize: 12,
                opacity: 0.65,
              }}
            >
              Gmail Message ID:{" "}
              {email.gmail_message_id}
            </div>
          )}
        </section>

        {/* THREAT ASSESSMENT */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Threat Assessment
              </h3>

              <p>
                Automated forensic risk
                assessment.
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

              <span>
                Threat Score / 100
              </span>
            </div>

            <div className="risk-reasons">
              <h4>
                Detection Reasons
              </h4>

              {reasons.length ? (
                <ul>
                  {reasons.map(
                    (
                      reason,
                      index
                    ) => (
                      <li key={index}>
                        {reason}
                      </li>
                    )
                  )}
                </ul>
              ) : (
                <p>
                  No suspicious indicators
                  detected.
                </p>
              )}
            </div>
          </div>
        </section>

        {/* DETAILED THREAT ANALYSIS */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Detailed Threat Analysis
              </h3>

              <p>
                Consolidated threat
                intelligence and forensic
                findings.
              </p>
            </div>
          </div>

          <div className="indicator-grid">
            <div className="indicator-card">
              <span className="indicator-number">
                {summary.total_indicators ??
                  indicators.length}
              </span>

              <strong>
                Total Indicators
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {summary.malicious ||
                  0}
              </span>

              <strong>
                Malicious
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {summary.suspicious ||
                  0}
              </span>

              <strong>
                Suspicious
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {summary.clean || 0}
              </span>

              <strong>
                Clean
              </strong>
            </div>
          </div>

          {indicators.length > 0 && (
            <div
              style={{
                marginTop: 20,
              }}
            >
              {indicators.map(
                (item, index) => {
                  const status =
                    item.status ||
                    "UNKNOWN";

                  const statusClass =
                    String(status)
                      .toLowerCase() ===
                    "malicious"
                      ? "risk-high"
                      : String(status)
                          .toLowerCase() ===
                        "suspicious"
                      ? "risk-medium"
                      : String(status)
                          .toLowerCase() ===
                        "clean"
                      ? "risk-low"
                      : "";

                  return (
                    <div
                      className="panel"
                      key={index}
                      style={{
                        marginBottom: 12,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent:
                            "space-between",
                          alignItems:
                            "center",
                          gap: 15,
                        }}
                      >
                        <strong
                          style={{
                            wordBreak:
                              "break-word",
                          }}
                        >
                          {item.indicator ||
                            "Unknown Indicator"}
                        </strong>

                        <span
                          className={`risk-badge ${statusClass}`}
                        >
                          {status}
                        </span>
                      </div>

                      <div
                        className="info-grid"
                        style={{
                          marginTop: 15,
                        }}
                      >
                        <div className="info-item">
                          <span>
                            Type
                          </span>

                          <strong>
                            {item.type ||
                              "Unknown"}
                          </strong>
                        </div>

                        <div className="info-item">
                          <span>
                            Source
                          </span>

                          <strong>
                            {item.source ||
                              "Threat Intelligence"}
                          </strong>
                        </div>

                        <div className="info-item">
                          <span>
                            Confidence
                          </span>

                          <strong>
                            {item.confidence ??
                              0}
                            %
                          </strong>
                        </div>

                        <div className="info-item">
                          <span>
                            Malicious
                          </span>

                          <strong>
                            {item.malicious ??
                              0}
                          </strong>
                        </div>

                        <div className="info-item">
                          <span>
                            Suspicious
                          </span>

                          <strong>
                            {item.suspicious ??
                              0}
                          </strong>
                        </div>

                        <div className="info-item">
                          <span>
                            Harmless
                          </span>

                          <strong>
                            {item.harmless ??
                              0}
                          </strong>
                        </div>

                        <div className="info-item">
                          <span>
                            Undetected
                          </span>

                          <strong>
                            {item.undetected ??
                              0}
                          </strong>
                        </div>

                        {item.abuse_confidence_score !==
                          undefined && (
                          <div className="info-item">
                            <span>
                              AbuseIPDB Confidence
                            </span>

                            <strong>
                              {
                                item.abuse_confidence_score
                              }
                              %
                            </strong>
                          </div>
                        )}

                        {item.total_reports !==
                          undefined && (
                          <div className="info-item">
                            <span>
                              Reports
                            </span>

                            <strong>
                              {
                                item.total_reports
                              }
                            </strong>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          )}
        </section>

        {/* INVESTIGATION SUMMARY */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Investigation Summary
              </h3>

              <p>
                High-level findings from
                the investigation.
              </p>
            </div>
          </div>

          <div className="indicator-grid">
            <div className="indicator-card">
              <span className="indicator-number">
                {urls.length}
              </span>

              <strong>
                URLs
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {domains.length}
              </span>

              <strong>
                Domains
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {ips.length}
              </span>

              <strong>
                IP Addresses
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {indicators.length}
              </span>

              <strong>
                Threat Indicators
              </strong>
            </div>
          </div>
        </section>

        {/* FORENSIC INDICATORS */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Forensic Indicators
              </h3>

              <p>
                Indicators extracted
                from the email.
              </p>
            </div>
          </div>

          <div className="indicator-grid">
            <div className="indicator-card">
              <span className="indicator-number">
                {urls.length}
              </span>

              <strong>
                URLs
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {domains.length}
              </span>

              <strong>
                Domains
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {ips.length}
              </span>

              <strong>
                IP Addresses
              </strong>
            </div>

            <div className="indicator-card">
              <span className="indicator-number">
                {received.length}
              </span>

              <strong>
                Received Headers
              </strong>
            </div>
          </div>

          {urls.length > 0 && (
            <div className="indicator-section">
              <h4>
                Extracted URLs
              </h4>

              <div className="tag-list">
                {urls.map(
                  (item, index) => (
                    <span
                      className="tag"
                      key={index}
                    >
                      {item}
                    </span>
                  )
                )}
              </div>
            </div>
          )}

          {domains.length > 0 && (
            <div className="indicator-section">
              <h4>
                Extracted Domains
              </h4>

              <div className="tag-list">
                {domains.map(
                  (item, index) => (
                    <span
                      className="tag"
                      key={index}
                    >
                      {item}
                    </span>
                  )
                )}
              </div>
            </div>
          )}

          {ips.length > 0 && (
            <div className="indicator-section">
              <h4>
                IP Addresses
              </h4>

              <div className="tag-list">
                {ips.map(
                  (item, index) => (
                    <span
                      className="tag ip-tag"
                      key={index}
                    >
                      {item}
                    </span>
                  )
                )}
              </div>
            </div>
          )}

          {received.length > 0 && (
            <div className="indicator-section">
              <h4>
                Received Headers
              </h4>

              <div className="tag-list">
                {received.map(
                  (item, index) => (
                    <span
                      className="tag"
                      key={index}
                    >
                      {item}
                    </span>
                  )
                )}
              </div>
            </div>
          )}
        </section>

        {/* AUTHENTICATION */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Email Authentication
              </h3>

              <p>
                SPF, DKIM and
                Authentication-Results.
              </p>
            </div>
          </div>

          <div className="auth-grid">
            <div className="auth-card">
              <span>
                SPF
              </span>

              <strong>
                {auth.spf ||
                  "Not Found"}
              </strong>
            </div>

            <div className="auth-card">
              <span>
                DKIM
              </span>

              <strong>
                {auth.dkim ||
                  "Not Found"}
              </strong>
            </div>

            <div className="auth-card">
              <span>
                Authentication Results
              </span>

              <strong>
                {auth.authentication_results ||
                  "Not available"}
              </strong>
            </div>
          </div>
        </section>

        {/* THREAT INTELLIGENCE */}

        {settings.threatIntel && (
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>
                  Threat Intelligence
                </h3>

                <p>
                  External intelligence
                  results.
                </p>
              </div>
            </div>

            <div className="indicator-grid">
              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.total_indicators ??
                    indicators.length}
                </span>

                <strong>
                  Total
                </strong>
              </div>

              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.malicious ||
                    0}
                </span>

                <strong>
                  Malicious
                </strong>
              </div>

              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.suspicious ||
                    0}
                </span>

                <strong>
                  Suspicious
                </strong>
              </div>

              <div className="indicator-card">
                <span className="indicator-number">
                  {summary.clean ||
                    0}
                </span>

                <strong>
                  Clean
                </strong>
              </div>
            </div>

            {indicators.length > 0 && (
              <div
                style={{
                  marginTop: 20,
                }}
              >
                {indicators.map(
                  (
                    item,
                    index
                  ) => (
                    <div
                      className="panel"
                      key={index}
                      style={{
                        marginBottom: 12,
                      }}
                    >
                      <strong>
                        {item.indicator ||
                          "Unknown"}
                      </strong>

                      <p>
                        Type:{" "}
                        {item.type ||
                          "Unknown"}
                        <br />

                        Status:{" "}
                        {item.status ||
                          "Unknown"}
                        <br />

                        Source:{" "}
                        {item.source ||
                          "Threat Intelligence"}
                        <br />

                        Confidence:{" "}
                        {item.confidence ??
                          0}
                        %
                      </p>
                    </div>
                  )
                )}
              </div>
            )}
          </section>
        )}

        {/* GEOLOCATION */}

        {settings.geolocation && (
          <section className="panel">
            <div className="panel-header">
              <div>
                <h3>
                  🌍 IP Geolocation
                </h3>

                <p>
                  Geographic intelligence
                  from public IPs.
                </p>
              </div>
            </div>

            {geo.length > 0 ? (
              <div className="geo-grid">
                {geo.map(
                  (
                    item,
                    index
                  ) => (
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
                            {item.ip ||
                              "Unknown IP"}
                          </h4>

                          <span>
                            {item.country ||
                              "Unknown"}
                          </span>
                        </div>
                      </div>

                      <div className="geo-details">
                        <div>
                          <span>
                            Country
                          </span>

                          <strong>
                            {item.country ||
                              "Unknown"}
                          </strong>
                        </div>

                        <div>
                          <span>
                            Region
                          </span>

                          <strong>
                            {item.region ||
                              "Unknown"}
                          </strong>
                        </div>

                        <div>
                          <span>
                            City
                          </span>

                          <strong>
                            {item.city ||
                              "Unknown"}
                          </strong>
                        </div>

                        <div>
                          <span>
                            Organization
                          </span>

                          <strong>
                            {item.organization ||
                              "Unknown"}
                          </strong>
                        </div>
                      </div>
                    </div>
                  )
                )}
              </div>
            ) : (
              <p>
                No public IP geolocation
                available.
              </p>
            )}
          </section>
        )}

        {/* MAP */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                🗺️ IP Geolocation Map
              </h3>

              <p>
                Visual representation
                of detected public IPs.
              </p>
            </div>
          </div>

          {geo.some(
            (item) =>
              item.latitude != null &&
              item.longitude != null
          ) ? (
            <MapContainer
              center={[
                Number(
                  geo.find(
                    (item) =>
                      item.latitude != null &&
                      item.longitude != null
                  ).latitude
                ),
                Number(
                  geo.find(
                    (item) =>
                      item.latitude != null &&
                      item.longitude != null
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

              {geo.map(
                (
                  item,
                  index
                ) =>
                  item.latitude != null &&
                  item.longitude != null ? (
                    <Marker
                      key={index}
                      position={[
                        Number(
                          item.latitude
                        ),
                        Number(
                          item.longitude
                        ),
                      ]}
                    >
                      <Popup>
                        <strong>
                          IP:{" "}
                          {item.ip ||
                            "Unknown"}
                        </strong>

                        <br />

                        Country:{" "}
                        {item.country ||
                          "Unknown"}

                        <br />

                        City:{" "}
                        {item.city ||
                          "Unknown"}

                        <br />

                        Organization:{" "}
                        {item.organization ||
                          "Unknown"}
                      </Popup>
                    </Marker>
                  ) : null
              )}
            </MapContainer>
          ) : (
            <p>
              No mappable public IP
              location.
            </p>
          )}
        </section>

        {/* EMAIL BODY */}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Email Body
              </h3>

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
            {body}
          </div>
        </section>

        {/* ACTIONS */}

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

  // =================================================
  // SETTINGS
  // =================================================

  const Settings = () => (
    <section
      className="panel"
      style={{
        padding: 28,
      }}
    >
      <div className="panel-header">
        <div>
          <h3>
            Settings
          </h3>

          <p>
            Configure SENTINEL analysis
            preferences.
          </p>
        </div>
      </div>

      <div
        style={{
          marginTop: 25,
        }}
      >
        <h4>
          Analysis Features
        </h4>

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
        ].map(
          ([
            key,
            title,
            description,
          ]) => (
            <div
              key={key}
              style={{
                display: "flex",
                justifyContent:
                  "space-between",
                alignItems: "center",
                padding: "18px",
                marginTop: "12px",
                border:
                  "1px solid #dbe1ea",
                borderRadius: "10px",
                gap: 20,
              }}
            >
              <div>
                <strong>
                  {title}
                </strong>

                <p
                  style={{
                    margin:
                      "5px 0 0",
                    opacity: 0.7,
                  }}
                >
                  {description}
                </p>
              </div>

              <button
                className="secondary-button"
                onClick={() =>
                  toggle(key)
                }
              >
                {settings[key]
                  ? "ON"
                  : "OFF"}
              </button>
            </div>
          )
        )}
      </div>

      <div
        style={{
          marginTop: 30,
        }}
      >
        <h4>
          Gmail Integration
        </h4>

        <div
          style={{
            padding: 18,
            border:
              "1px solid #dbe1ea",
            borderRadius: 10,
            marginTop: 12,
          }}
        >
          <strong>
            Gmail Status
          </strong>

          <p
            style={{
              margin:
                "6px 0 12px",
              opacity: 0.7,
            }}
          >
            {gmailConnected
              ? `Connected: ${
                  gmailEmail ||
                  "Gmail account"
                }`
              : "Not connected"}
          </p>

          {gmailConnected ? (
            <button
              className="secondary-button"
              onClick={
                disconnectGmail
              }
            >
              Disconnect Gmail
            </button>
          ) : (
            <button
              className="primary-button"
              onClick={connectGmail}
            >
              Connect Gmail
            </button>
          )}
        </div>
      </div>

      <div
        style={{
          marginTop: 30,
        }}
      >
        <h4>
          System Status
        </h4>

        <div className="indicator-grid">
          <div className="indicator-card">
            <strong>
              ● Backend
            </strong>

            <span>
              Connected
            </span>
          </div>

          <div className="indicator-card">
            <strong>
              ● Forensic Engine
            </strong>

            <span>
              Ready
            </span>
          </div>

          <div className="indicator-card">
            <strong>
              ● Threat Intelligence
            </strong>

            <span>
              Ready
            </span>
          </div>

          <div className="indicator-card">
            <strong>
              ● Geolocation
            </strong>

            <span>
              Ready
            </span>
          </div>

          <div className="indicator-card">
            <strong>
              ● Gmail API
            </strong>

            <span>
              {gmailConnected
                ? "Connected"
                : "Available"}
            </span>
          </div>
        </div>
      </div>

      <div
        style={{
          marginTop: 30,
        }}
      >
        <h4>
          About SENTINEL
        </h4>

        <p>
          SENTINEL is an Email Threat
          Intelligence & Forensic
          Analysis Platform designed
          to analyze suspicious email
          files and provide investigation
          insights.
        </p>

        <p
          style={{
            opacity: 0.7,
          }}
        >
          Version 1.0 • Security
          Operations Platform
        </p>
      </div>
    </section>
  );

  // =================================================
  // REPORTS
  // =================================================

  const Reports = () => (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>
            📄 Security Report
          </h3>

          <p>
            Generate a professional
            report for the current
            investigation.
          </p>
        </div>
      </div>

      {data ? (
        <div
          style={{
            padding: 20,
          }}
        >
          <h4>
            Investigation Report Ready
          </h4>

          <p>
            Risk Level:{" "}
            <strong>
              {riskLevel}
            </strong>
          </p>

          <p>
            Risk Score:{" "}
            <strong>
              {riskScore} / 100
            </strong>
          </p>

          <p>
            Threat Indicators:{" "}
            <strong>
              {indicators.length}
            </strong>
          </p>

          <button
            className="primary-button"
            onClick={
              generateReport
            }
          >
            📄 Generate PDF / Print Report
          </button>
        </div>
      ) : (
        <div className="empty-state">
          <h3>
            No Report Available
          </h3>

          <p>
            Analyze an email first
            to generate a report.
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

  // =================================================
  // MAIN UI
  // =================================================

  return (
    <div className="app">
      {/* SIDEBAR */}

      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            S
          </div>

          <div>
            <h1>
              SENTINEL
            </h1>

            <span>
              Threat Intelligence
            </span>
          </div>
        </div>

        <nav className="navigation">
          <button
            className={`nav-item ${
              page === "Dashboard"
                ? "active"
                : ""
            }`}
            onClick={
              dashboard
            }
          >
            <span>
              ▦
            </span>

            Dashboard
          </button>

          <button
            className={`nav-item ${
              page === "Analyze Email"
                ? "active"
                : ""
            }`}
            onClick={
              uploadPage
            }
          >
            <span>
              ✉
            </span>

            Analyze Email
          </button>

          <button
            className={`nav-item ${
              page === "Gmail"
                ? "active"
                : ""
            }`}
            onClick={() => {
              setPage("Gmail");
              setGmailError("");

              window.scrollTo({
                top: 0,
                behavior: "smooth",
              });
            }}
          >
            <span>
              📧
            </span>

            Gmail
          </button>

          <button
            className={`nav-item ${
              page === "Investigate"
                ? "active"
                : ""
            }`}
            onClick={
              investigate
            }
          >
            <span>
              ⌕
            </span>

            Investigate
          </button>

          <button
            className={`nav-item ${
              page === "Reports"
                ? "active"
                : ""
            }`}
            onClick={
              reports
            }
          >
            <span>
              ▤
            </span>

            Reports
          </button>

          <button
            className={`nav-item ${
              page === "History"
                ? "active"
                : ""
            }`}
            onClick={() => {
              setPage("History");

              window.scrollTo({
                top: 0,
                behavior: "smooth",
              });
            }}
          >
            <span>
              ◷
            </span>

            History
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
            <span>
              ⚙
            </span>

            Settings
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>
                System Online
              </strong>

              <small>
                All services operational
              </small>
            </div>
          </div>

          <div
            style={{
              marginTop: 12,
              fontSize: 11,
              lineHeight: 1.7,
            }}
          >
            <div>
              ● SENTINEL Engine Ready
            </div>

            <div>
              ● Threat Intelligence Ready
            </div>

            <div>
              ● Forensic Analyzer Ready
            </div>

            <div>
              ● Gmail Integration{" "}
              {gmailConnected
                ? "Connected"
                : "Ready"}
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN */}

      <main className="main-content">
        <header className="topbar">
          <div>
            <h2>
              {page}
            </h2>

            <p>
              Email threat intelligence &
              forensic analysis
            </p>
          </div>

          <div className="analyst">
            <div className="analyst-avatar">
              A
            </div>

            <div>
              <strong>
                Analyst
              </strong>

              <span>
                Security Operations
              </span>
            </div>
          </div>
        </header>

        <div className="content">
          {page === "Dashboard" && (
            <Dashboard />
          )}

          {page === "Analyze Email" && (
            <>
              <UploadSection />

              {data && (
                <Results />
              )}
            </>
          )}

          {page === "Gmail" && (
            <Gmail />
          )}

          {page === "Investigate" && (
            <Results />
          )}

          {page === "Reports" && (
            <Reports />
          )}

          {page === "History" && (
            <History />
          )}

          {page === "Settings" && (
            <Settings />
          )}
        </div>
      </main>
    </div>
  );
}

export default App;