import { useEffect, useMemo, useState } from "react";

import {
  getDashboard,
  getVulnerabilities,
} from "./services/api";

import {
  Activity,
  AlertCircle,
  BarChart3,
  LayoutDashboard,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
} from "lucide-react";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";


/* =========================================================
   APPLICATION CONFIGURATION
   ========================================================= */

const navigation = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: LayoutDashboard,
  },
  {
    id: "vulnerabilities",
    label: "Vulnerabilities",
    icon: ShieldAlert,
  },
  {
    id: "analytics",
    label: "ML Analytics",
    icon: BarChart3,
  },
  {
    id: "settings",
    label: "Settings",
    icon: Settings,
  },
];

const priorityColors = {
  High: "#ff4d67",
  Medium: "#f5c451",
  Low: "#31d598",
};


/* =========================================================
   SMALL REUSABLE COMPONENTS
   ========================================================= */

function StatCard({ title, value, color }) {
  return (
    <article
      className="stat-card"
      style={{ "--stat-color": color }}
    >
      <span>{title}</span>
      <strong>{value}</strong>
    </article>
  );
}


function PriorityBadge({ priority }) {
  const safePriority = priority || "Unknown";

  return (
    <span
      className={`priority-badge priority-${safePriority.toLowerCase()}`}
    >
      {safePriority}
    </span>
  );
}


function RiskScore({ score }) {
  const numericScore = Number(score) || 0;
  const safeScore = Math.min(
    Math.max(numericScore, 0),
    100
  );

  let color = "#31d598";

  if (safeScore >= 75) {
    color = "#ff4d67";
  } else if (safeScore >= 45) {
    color = "#f5c451";
  }

  return (
    <div className="risk-score">
      <div className="risk-track">
        <div
          className="risk-fill"
          style={{
            width: `${safeScore}%`,
            backgroundColor: color,
          }}
        />
      </div>

      <strong style={{ color }}>
        {safeScore}
      </strong>
    </div>
  );
}


function LoadingScreen() {
  return (
    <section className="panel">
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
        }}
      >
        <RefreshCw size={21} />

        <div>
          <h2>Loading vulnerability data</h2>

          <p>
            Reading processed NVD records from the
            FastAPI backend.
          </p>
        </div>
      </div>
    </section>
  );
}


function ErrorScreen({ message, onRetry }) {
  return (
    <section className="panel">
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "12px",
        }}
      >
        <AlertCircle
          size={22}
          color="#ff4d67"
        />

        <div>
          <h2>Backend connection failed</h2>

          <p>{message}</p>

          <button
            className="primary-button"
            onClick={onRetry}
          >
            <RefreshCw size={15} />
            Try Again
          </button>
        </div>
      </div>
    </section>
  );
}


function EmptyScreen() {
  return (
    <section className="panel">
      <h2>No vulnerability records found</h2>

      <p>
        FastAPI returned an empty list. Check that
        backend/data/processed_nvd_data.csv exists and
        contains records.
      </p>
    </section>
  );
}


/* =========================================================
   VULNERABILITY TABLE
   ========================================================= */

function VulnerabilityTable({
  data,
  onSelect,
}) {
  if (!Array.isArray(data) || data.length === 0) {
    return <EmptyScreen />;
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>CVSS</th>
            <th>Severity</th>
            <th>Priority</th>
            <th>Risk Score</th>
            <th>Confidence</th>
            <th>Attack Vector</th>
            <th>Published</th>
          </tr>
        </thead>

        <tbody>
          {data.map((item) => (
            <tr
              key={item.cveId}
              onClick={() => onSelect(item)}
            >
              <td className="cve-id">
                {item.cveId || "Unknown"}
              </td>

              <td>
                {Number(item.cvss || 0).toFixed(1)}
              </td>

              <td>
                {item.severity || "UNKNOWN"}
              </td>

              <td>
                <PriorityBadge
                  priority={item.priority}
                />
              </td>

              <td>
                <RiskScore
                  score={item.riskScore}
                />
              </td>

              <td>
                {item.confidence == null
                  ? "Pending"
                  : `${item.confidence}%`}
              </td>

              <td>
                {item.attackVector || "UNKNOWN"}
              </td>

              <td>
                {item.published || "Unknown"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


/* =========================================================
   DASHBOARD PAGE
   ========================================================= */

function Dashboard({
  data,
  stats,
  onSelect,
}) {
  const highCount = data.filter(
    (item) => item.priority === "High"
  ).length;

  const mediumCount = data.filter(
    (item) => item.priority === "Medium"
  ).length;

  const lowCount = data.filter(
    (item) => item.priority === "Low"
  ).length;

  const calculatedAverageRisk =
    data.length > 0
      ? Math.round(
          data.reduce(
            (total, item) =>
              total +
              Number(item.riskScore || 0),
            0
          ) / data.length
        )
      : 0;

  const total =
    stats?.total_vulnerabilities ??
    data.length;

  const high =
    stats?.high_priority ??
    highCount;

  const medium =
    stats?.medium_priority ??
    mediumCount;

  const low =
    stats?.low_priority ??
    lowCount;

  const averageRisk =
    stats?.average_risk ??
    calculatedAverageRisk;

  const priorityData = [
    {
      name: "High",
      value: highCount,
    },
    {
      name: "Medium",
      value: mediumCount,
    },
    {
      name: "Low",
      value: lowCount,
    },
  ];

  const severityData = Object.entries(
    data.reduce((counts, item) => {
      const severity =
        item.severity || "UNKNOWN";

      counts[severity] =
        (counts[severity] || 0) + 1;

      return counts;
    }, {})
  ).map(([name, value]) => ({
    name,
    value,
  }));

  const highestRisk = [...data]
    .sort(
      (first, second) =>
        Number(second.riskScore || 0) -
        Number(first.riskScore || 0)
    )
    .slice(0, 10);

  return (
    <>
      <div className="stats-grid">
        <StatCard
          title="Total Vulnerabilities"
          value={total}
          color="#41c7ff"
        />

        <StatCard
          title="High Priority"
          value={high}
          color="#ff4d67"
        />

        <StatCard
          title="Medium Priority"
          value={medium}
          color="#f5c451"
        />

        <StatCard
          title="Low Priority"
          value={low}
          color="#31d598"
        />

        <StatCard
  title="Average Risk (0-100)"
  value={averageRisk}
  color="#a78bfa"
/>
      </div>

      <div className="chart-grid">
        <section className="panel">
          <h2>Priority Distribution</h2>

          <p>
            Priority classifications returned by the
            vulnerability API
          </p>

          <ResponsiveContainer
            width="100%"
            height={280}
          >
            <PieChart>
              <Pie
                data={priorityData}
                dataKey="value"
                nameKey="name"
                innerRadius={70}
                outerRadius={105}
                paddingAngle={3}
              >
                {priorityData.map((item) => (
                  <Cell
                    key={item.name}
                    fill={
                      priorityColors[item.name]
                    }
                  />
                ))}
              </Pie>

              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </section>

        <section className="panel">
          <h2>Severity Distribution</h2>

          <p>
            Distribution of NVD CVSS severity values
          </p>

          <ResponsiveContainer
            width="100%"
            height={280}
          >
            <BarChart data={severityData}>
              <CartesianGrid
                stroke="#1e3148"
                vertical={false}
              />

              <XAxis
                dataKey="name"
                stroke="#8193aa"
              />

              <YAxis stroke="#8193aa" />

              <Tooltip />

              <Bar
                dataKey="value"
                fill="#41c7ff"
                radius={[5, 5, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>
              Highest-Risk Vulnerabilities
            </h2>

            <p>
              Real vulnerability records ranked by
              current risk score
            </p>
          </div>
        </div>

        <VulnerabilityTable
          data={highestRisk}
          onSelect={onSelect}
        />
      </section>
    </>
  );
}


/* =========================================================
   VULNERABILITIES PAGE
   ========================================================= */

function VulnerabilitiesPage({
  data,
  onSelect,
}) {
  const [search, setSearch] =
    useState("");

  const [priority, setPriority] =
    useState("All");

  const [severity, setSeverity] =
    useState("All");

  const filteredData = useMemo(() => {
    return data.filter((item) => {
      const searchText =
        search.trim().toLowerCase();

      const cveId = String(
        item.cveId || ""
      ).toLowerCase();

      const description = String(
        item.description || ""
      ).toLowerCase();

      const matchesSearch =
        cveId.includes(searchText) ||
        description.includes(searchText);

      const matchesPriority =
        priority === "All" ||
        item.priority === priority;

      const matchesSeverity =
        severity === "All" ||
        item.severity === severity;

      return (
        matchesSearch &&
        matchesPriority &&
        matchesSeverity
      );
    });
  }, [
    search,
    priority,
    severity,
    data,
  ]);

  return (
    <section className="panel">
      <div className="filters">
        <div className="search-box">
          <Search size={17} />

          <input
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
            placeholder="Search CVE ID or description"
          />
        </div>

        <select
          value={priority}
          onChange={(event) =>
            setPriority(event.target.value)
          }
        >
          <option value="All">
            All priorities
          </option>

          <option value="High">
            High
          </option>

          <option value="Medium">
            Medium
          </option>

          <option value="Low">
            Low
          </option>
        </select>

        <select
          value={severity}
          onChange={(event) =>
            setSeverity(event.target.value)
          }
        >
          <option value="All">
            All severities
          </option>

          <option value="CRITICAL">
            Critical
          </option>

          <option value="HIGH">
            High
          </option>

          <option value="MEDIUM">
            Medium
          </option>

          <option value="LOW">
            Low
          </option>

          <option value="UNKNOWN">
            Unknown
          </option>
        </select>
      </div>

      <p className="result-count">
        {filteredData.length} vulnerabilities found
      </p>

      <VulnerabilityTable
        data={filteredData}
        onSelect={onSelect}
      />
    </section>
  );
}


/* =========================================================
   VULNERABILITY DETAILS PAGE
   ========================================================= */

function VulnerabilityDetails({
  vulnerability,
  onBack,
}) {
  if (!vulnerability) {
    return (
      <section className="panel">
        <h2>No vulnerability selected</h2>

        <button
          className="secondary-button"
          onClick={onBack}
        >
          Back to vulnerabilities
        </button>
      </section>
    );
  }

  const reasons = [];
  const cvss = Number(
    vulnerability.cvss || 0
  );

  if (cvss >= 9) {
    reasons.push(
      "Critical CVSS base score"
    );
  } else if (cvss >= 7) {
    reasons.push(
      "High CVSS base score"
    );
  }

  if (
    vulnerability.attackVector === "NETWORK"
  ) {
    reasons.push(
      "Potential exploitation through a network"
    );
  }

  if (
    vulnerability.attackComplexity === "LOW"
  ) {
    reasons.push(
      "Low attack complexity"
    );
  }

  if (
    vulnerability.privilegesRequired ===
    "NONE"
  ) {
    reasons.push(
      "No existing attacker privileges required"
    );
  }

  if (
    vulnerability.userInteraction ===
    "NONE"
  ) {
    reasons.push(
      "No victim interaction required"
    );
  }

  if (
    Number(
      vulnerability.referenceCount || 0
    ) >= 10
  ) {
    reasons.push(
      "Large number of public references"
    );
  }

  if (vulnerability.hasCisaKev) {
    reasons.push(
      "Listed in the CISA KEV catalog"
    );
  }

  if (reasons.length === 0) {
    reasons.push(
      "No major high-risk technical indicators were identified"
    );
  }

  return (
    <>
      <button
        className="secondary-button"
        onClick={onBack}
      >
        ← Back to vulnerabilities
      </button>

      <div className="details-layout">
        <section className="panel">
          <div className="details-heading">
            <div>
              <span className="cve-id">
                {vulnerability.cveId}
              </span>

              <h2>
                {vulnerability.severity ||
                  "UNKNOWN"}{" "}
                vulnerability
              </h2>
            </div>

            <div className="score-circle">
              <strong>
                {Math.min(
                  Number(
                    vulnerability.riskScore ||
                      0
                  ),
                  100
                )}
              </strong>

              <span>Risk</span>
            </div>
          </div>

          <p className="description">
            {vulnerability.description ||
              "No description is available."}
          </p>

          <div className="details-grid">
            <div>
              <span>CVSS Score</span>
              <strong>
                {cvss.toFixed(1)}
              </strong>
            </div>

            <div>
              <span>Priority</span>

              <PriorityBadge
                priority={
                  vulnerability.priority
                }
              />
            </div>

            <div>
              <span>Model Confidence</span>

              <strong>
                {vulnerability.confidence ==
                null
                  ? "Pending"
                  : `${vulnerability.confidence}%`}
              </strong>
            </div>

            <div>
              <span>Attack Vector</span>
              <strong>
                {vulnerability.attackVector ||
                  "UNKNOWN"}
              </strong>
            </div>

            <div>
              <span>
                Attack Complexity
              </span>

              <strong>
                {vulnerability.attackComplexity ||
                  "UNKNOWN"}
              </strong>
            </div>

            <div>
              <span>
                Privileges Required
              </span>

              <strong>
                {vulnerability.privilegesRequired ||
                  "UNKNOWN"}
              </strong>
            </div>

            <div>
              <span>User Interaction</span>

              <strong>
                {vulnerability.userInteraction ||
                  "UNKNOWN"}
              </strong>
            </div>

            <div>
              <span>Weakness Count</span>

              <strong>
                {Number(
                  vulnerability.weaknessCount ||
                    0
                )}
              </strong>
            </div>

            <div>
              <span>Reference Count</span>

              <strong>
                {Number(
                  vulnerability.referenceCount ||
                    0
                )}
              </strong>
            </div>

            <div>
              <span>CISA KEV</span>

              <strong>
                {vulnerability.hasCisaKev
                  ? "Yes"
                  : "No"}
              </strong>
            </div>

            <div>
              <span>Published</span>
              <strong>
                {vulnerability.published ||
                  "Unknown"}
              </strong>
            </div>
          </div>
        </section>

        <aside className="panel">
          <h2>
            Why was this prioritized?
          </h2>

          <div className="reason-list">
            {reasons.map((reason) => (
              <div
                className="reason"
                key={reason}
              >
                <span>✓</span>
                {reason}
              </div>
            ))}
          </div>

          <p className="explanation-note">
            The explanation is based on the
            vulnerability properties supplied by
            the FastAPI backend.
          </p>
        </aside>
      </div>
    </>
  );
}


/* =========================================================
   ANALYTICS PAGE
   ========================================================= */

function AnalyticsPage({ data }) {
  const priorityData = [
    {
      name: "High",
      value: data.filter(
        (item) =>
          item.priority === "High"
      ).length,
    },
    {
      name: "Medium",
      value: data.filter(
        (item) =>
          item.priority === "Medium"
      ).length,
    },
    {
      name: "Low",
      value: data.filter(
        (item) =>
          item.priority === "Low"
      ).length,
    },
  ];

  return (
    <>
      <div className="analytics-metrics">
        <StatCard
          title="Records Loaded"
          value={data.length}
          color="#41c7ff"
        />

        <StatCard
          title="Model"
          value="Random Forest"
          color="#31d598"
        />

        <StatCard
          title="Target Classes"
          value="3"
          color="#f5c451"
        />

        <StatCard
          title="Data Source"
          value="NVD"
          color="#a78bfa"
        />
      </div>

      <div className="chart-grid">
        <section className="panel">
          <h2>
            Priority Distribution
          </h2>

          <p>
            Distribution calculated from the real
            vulnerability API response
          </p>

          <ResponsiveContainer
            width="100%"
            height={280}
          >
            <BarChart data={priorityData}>
              <CartesianGrid
                stroke="#1e3148"
                vertical={false}
              />

              <XAxis
                dataKey="name"
                stroke="#8193aa"
              />

              <YAxis stroke="#8193aa" />
              <Tooltip />

              <Bar dataKey="value">
                {priorityData.map((item) => (
                  <Cell
                    key={item.name}
                    fill={
                      priorityColors[item.name]
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="panel analytics-placeholder">
          <BarChart3 size={36} />

          <h2>Model Evaluation</h2>

          <p>
            Accuracy, precision, recall, F1-score,
            feature importance, and the confusion
            matrix will be loaded through a future
            analytics endpoint.
          </p>
        </section>
      </div>
    </>
  );
}


/* =========================================================
   SETTINGS PAGE
   ========================================================= */

function SettingsPage({
  onRefresh,
  loading,
  recordCount,
  apiConnected,
}) {
  return (
    <div className="settings-grid">
      <section className="panel">
        <h2>FastAPI Connection</h2>

        <p
          className={
            apiConnected
              ? "connected"
              : ""
          }
        >
          {apiConnected
            ? "● Backend connected"
            : "● Backend disconnected"}
        </p>

        <p>
          Vulnerability records are loaded from the
          processed NVD dataset through FastAPI.
        </p>
      </section>

      <section className="panel">
        <h2>Machine Learning Model</h2>

        <dl>
          <div>
            <dt>Algorithm</dt>
            <dd>
              Random Forest Classifier
            </dd>
          </div>

          <div>
            <dt>Loaded API Records</dt>
            <dd>{recordCount}</dd>
          </div>

          <div>
            <dt>Status</dt>
            <dd className="connected">
              Ready
            </dd>
          </div>
        </dl>
      </section>

      <section className="panel">
        <h2>Data Refresh</h2>

        <p>
          Reload dashboard statistics and
          vulnerabilities from FastAPI.
        </p>

        <button
          className="primary-button"
          onClick={onRefresh}
          disabled={loading}
        >
          <RefreshCw size={15} />

          {loading
            ? "Refreshing..."
            : "Refresh API Data"}
        </button>
      </section>
    </div>
  );
}


/* =========================================================
   MAIN APPLICATION
   ========================================================= */

export default function App() {
  const [activePage, setActivePage] =
    useState("dashboard");

  const [
    selectedVulnerability,
    setSelectedVulnerability,
  ] = useState(null);

  const [
    dashboardStats,
    setDashboardStats,
  ] = useState(null);

  const [
    vulnerabilitiesData,
    setVulnerabilitiesData,
  ] = useState([]);

  const [loading, setLoading] =
    useState(true);

  const [apiError, setApiError] =
    useState("");

  async function loadApplicationData() {
    try {
      setLoading(true);
      setApiError("");

      const [
        dashboardResponse,
        vulnerabilitiesResponse,
      ] = await Promise.all([
        getDashboard(),
        getVulnerabilities(),
      ]);

      if (
        !Array.isArray(
          vulnerabilitiesResponse
        )
      ) {
        throw new Error(
          "The vulnerabilities endpoint did not return an array."
        );
      }

      setDashboardStats(
        dashboardResponse
      );

      setVulnerabilitiesData(
        vulnerabilitiesResponse
      );
    } catch (error) {
      console.error(
        "Backend connection error:",
        error
      );

      setDashboardStats(null);
      setVulnerabilitiesData([]);

      setApiError(
        error.message ||
          "The FastAPI backend could not be reached."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadApplicationData();
  }, []);

  function openVulnerability(item) {
    setSelectedVulnerability(item);
    setActivePage("details");
  }

  function closeVulnerability() {
    setSelectedVulnerability(null);
    setActivePage("vulnerabilities");
  }

  function renderCurrentPage() {
    if (activePage === "details") {
      return (
        <VulnerabilityDetails
          vulnerability={
            selectedVulnerability
          }
          onBack={closeVulnerability}
        />
      );
    }

    if (
      activePage === "vulnerabilities"
    ) {
      return (
        <VulnerabilitiesPage
          data={vulnerabilitiesData}
          onSelect={openVulnerability}
        />
      );
    }

    if (activePage === "analytics") {
      return (
        <AnalyticsPage
          data={vulnerabilitiesData}
        />
      );
    }

    if (activePage === "settings") {
      return (
        <SettingsPage
          onRefresh={
            loadApplicationData
          }
          loading={loading}
          recordCount={
            vulnerabilitiesData.length
          }
          apiConnected={!apiError}
        />
      );
    }

    return (
      <Dashboard
        data={vulnerabilitiesData}
        stats={dashboardStats}
        onSelect={openVulnerability}
      />
    );
  }

  const pageTitle =
    activePage === "details"
      ? "Vulnerability Details"
      : navigation.find(
          (item) =>
            item.id === activePage
        )?.label || "Dashboard";

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert size={27} />

          <div>
            <strong>VULN</strong>
            <span>PRIORITIZER</span>
          </div>
        </div>

        <nav>
          {navigation.map((item) => {
            const Icon = item.icon;

            const navigationIsActive =
              activePage === item.id ||
              (
                activePage === "details" &&
                item.id ===
                  "vulnerabilities"
              );

            return (
              <button
                key={item.id}
                className={
                  navigationIsActive
                    ? "nav-button active"
                    : "nav-button"
                }
                onClick={() => {
                  setActivePage(item.id);
                }}
              >
                <Icon size={17} />
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="system-status">
          <Activity size={16} />

          <div>
            <strong>FastAPI</strong>

            <span>
              {apiError
                ? "Disconnected"
                : "Connected"}
            </span>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <h1>{pageTitle}</h1>

            <p>
              Machine Learning-Based
              Vulnerability Prioritization
            </p>
          </div>

          <span
            className="online-indicator"
            style={{
              color: apiError
                ? "#ff4d67"
                : "#31d598",
            }}
          >
            {apiError
              ? "● BACKEND OFFLINE"
              : "● SYSTEM ONLINE"}
          </span>
        </header>

        <div className="page">
          {loading && (
            <LoadingScreen />
          )}

          {!loading && apiError && (
            <ErrorScreen
              message={apiError}
              onRetry={
                loadApplicationData
              }
            />
          )}

          {!loading &&
            !apiError &&
            vulnerabilitiesData.length ===
              0 && <EmptyScreen />}

          {!loading &&
            !apiError &&
            vulnerabilitiesData.length >
              0 &&
            renderCurrentPage()}
        </div>
      </main>
    </div>
  );
}