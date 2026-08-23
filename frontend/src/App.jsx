import { useMemo, useState } from "react";

import {
  Activity,
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


const vulnerabilities = [
  {
    cveId: "CVE-2024-24576",
    description:
      "Critical vulnerability that may allow remote code execution.",
    cvss: 10.0,
    severity: "CRITICAL",
    priority: "High",
    riskScore: 96,
    confidence: 97,
    attackVector: "NETWORK",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    weaknessCount: 2,
    referenceCount: 18,
    published: "2024-01-30",
  },
  {
    cveId: "CVE-2024-29022",
    description:
      "Network-accessible vulnerability requiring urgent remediation.",
    cvss: 8.8,
    severity: "HIGH",
    priority: "High",
    riskScore: 86,
    confidence: 94,
    attackVector: "NETWORK",
    privilegesRequired: "LOW",
    userInteraction: "NONE",
    weaknessCount: 1,
    referenceCount: 12,
    published: "2024-03-12",
  },
  {
    cveId: "CVE-2024-3384",
    description:
      "High-severity vulnerability with moderate exploitation risk.",
    cvss: 7.5,
    severity: "HIGH",
    priority: "Medium",
    riskScore: 65,
    confidence: 91,
    attackVector: "LOCAL",
    privilegesRequired: "LOW",
    userInteraction: "REQUIRED",
    weaknessCount: 1,
    referenceCount: 8,
    published: "2024-03-28",
  },
  {
    cveId: "CVE-2024-1874",
    description:
      "Medium-severity local vulnerability with limited impact.",
    cvss: 4.3,
    severity: "MEDIUM",
    priority: "Low",
    riskScore: 31,
    confidence: 89,
    attackVector: "LOCAL",
    privilegesRequired: "HIGH",
    userInteraction: "REQUIRED",
    weaknessCount: 1,
    referenceCount: 4,
    published: "2024-04-03",
  },
];


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
  return (
    <span
      className={`priority-badge priority-${priority.toLowerCase()}`}
    >
      {priority}
    </span>
  );
}


function RiskScore({ score }) {
  const color =
    score >= 75
      ? "#ff4d67"
      : score >= 45
      ? "#f5c451"
      : "#31d598";

  return (
    <div className="risk-score">
      <div className="risk-track">
        <div
          className="risk-fill"
          style={{
            width: `${score}%`,
            backgroundColor: color,
          }}
        />
      </div>

      <strong style={{ color }}>{score}</strong>
    </div>
  );
}


function VulnerabilityTable({ data, onSelect }) {
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
              <td className="cve-id">{item.cveId}</td>
              <td>{item.cvss.toFixed(1)}</td>
              <td>{item.severity}</td>

              <td>
                <PriorityBadge priority={item.priority} />
              </td>

              <td>
                <RiskScore score={item.riskScore} />
              </td>

              <td>{item.confidence}%</td>
              <td>{item.attackVector}</td>
              <td>{item.published}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


function Dashboard({ data, onSelect }) {
  const high = data.filter(
    (item) => item.priority === "High"
  ).length;

  const medium = data.filter(
    (item) => item.priority === "Medium"
  ).length;

  const low = data.filter(
    (item) => item.priority === "Low"
  ).length;

  const averageRisk = Math.round(
    data.reduce(
      (total, item) => total + item.riskScore,
      0
    ) / data.length
  );

  const priorityData = [
    { name: "High", value: high },
    { name: "Medium", value: medium },
    { name: "Low", value: low },
  ];

  const severityData = Object.entries(
    data.reduce((result, item) => {
      result[item.severity] =
        (result[item.severity] || 0) + 1;

      return result;
    }, {})
  ).map(([name, value]) => ({
    name,
    value,
  }));

  return (
    <>
      <div className="stats-grid">
        <StatCard
          title="Total Vulnerabilities"
          value={data.length}
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
          title="Average Risk"
          value={averageRisk}
          color="#a78bfa"
        />
      </div>

      <div className="chart-grid">
        <section className="panel">
          <h2>Priority Distribution</h2>
          <p>Machine-learning priority classifications</p>

          <ResponsiveContainer width="100%" height={280}>
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
                    fill={priorityColors[item.name]}
                  />
                ))}
              </Pie>

              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </section>

        <section className="panel">
          <h2>Severity Distribution</h2>
          <p>Distribution of NVD CVSS severity levels</p>

          <ResponsiveContainer width="100%" height={280}>
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
            <h2>Highest-Risk Vulnerabilities</h2>
            <p>
              Vulnerabilities ranked using predicted risk
              scores
            </p>
          </div>
        </div>

        <VulnerabilityTable
          data={[...data]
            .sort(
              (first, second) =>
                second.riskScore - first.riskScore
            )
            .slice(0, 10)}
          onSelect={onSelect}
        />
      </section>
    </>
  );
}


function VulnerabilitiesPage({ data, onSelect }) {
  const [search, setSearch] = useState("");
  const [priority, setPriority] = useState("All");
  const [severity, setSeverity] = useState("All");

  const filteredData = useMemo(() => {
    return data.filter((item) => {
      const searchText = search.toLowerCase();

      const matchesSearch =
        item.cveId
          .toLowerCase()
          .includes(searchText) ||
        item.description
          .toLowerCase()
          .includes(searchText);

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
  }, [search, priority, severity, data]);

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
          <option>All</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>

        <select
          value={severity}
          onChange={(event) =>
            setSeverity(event.target.value)
          }
        >
          <option>All</option>
          <option>CRITICAL</option>
          <option>HIGH</option>
          <option>MEDIUM</option>
          <option>LOW</option>
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


function VulnerabilityDetails({
  vulnerability,
  onBack,
}) {
  if (!vulnerability) {
    return null;
  }

  const reasons = [];

  if (vulnerability.cvss >= 9) {
    reasons.push("Critical CVSS base score");
  } else if (vulnerability.cvss >= 7) {
    reasons.push("High CVSS base score");
  }

  if (vulnerability.attackVector === "NETWORK") {
    reasons.push(
      "Potential exploitation through a network"
    );
  }

  if (
    vulnerability.privilegesRequired === "NONE"
  ) {
    reasons.push(
      "No existing attacker privileges required"
    );
  }

  if (vulnerability.userInteraction === "NONE") {
    reasons.push(
      "No victim user interaction required"
    );
  }

  if (vulnerability.referenceCount >= 10) {
    reasons.push(
      "Large number of public vulnerability references"
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
                {vulnerability.severity} vulnerability
              </h2>
            </div>

            <div className="score-circle">
              <strong>
                {vulnerability.riskScore}
              </strong>
              <span>Risk</span>
            </div>
          </div>

          <p className="description">
            {vulnerability.description}
          </p>

          <div className="details-grid">
            <div>
              <span>CVSS Score</span>
              <strong>{vulnerability.cvss}</strong>
            </div>

            <div>
              <span>Predicted Priority</span>
              <PriorityBadge
                priority={vulnerability.priority}
              />
            </div>

            <div>
              <span>Model Confidence</span>
              <strong>
                {vulnerability.confidence}%
              </strong>
            </div>

            <div>
              <span>Attack Vector</span>
              <strong>
                {vulnerability.attackVector}
              </strong>
            </div>

            <div>
              <span>Privileges Required</span>
              <strong>
                {vulnerability.privilegesRequired}
              </strong>
            </div>

            <div>
              <span>User Interaction</span>
              <strong>
                {vulnerability.userInteraction}
              </strong>
            </div>

            <div>
              <span>Weakness Count</span>
              <strong>
                {vulnerability.weaknessCount}
              </strong>
            </div>

            <div>
              <span>Reference Count</span>
              <strong>
                {vulnerability.referenceCount}
              </strong>
            </div>

            <div>
              <span>Published</span>
              <strong>
                {vulnerability.published}
              </strong>
            </div>
          </div>
        </section>

        <aside className="panel">
          <h2>Why was this prioritized?</h2>

          <div className="reason-list">
            {reasons.map((reason) => (
              <div className="reason" key={reason}>
                <span>✓</span>
                {reason}
              </div>
            ))}
          </div>

          <p className="explanation-note">
            These security characteristics contributed
            to the machine-learning prediction.
          </p>
        </aside>
      </div>
    </>
  );
}


function AnalyticsPage() {
  return (
    <>
      <div className="analytics-metrics">
        <StatCard
          title="Accuracy"
          value="96.57%"
          color="#41c7ff"
        />

        <StatCard
          title="Precision"
          value="96.70%"
          color="#31d598"
        />

        <StatCard
          title="Recall"
          value="96.57%"
          color="#f5c451"
        />

        <StatCard
          title="F1 Score"
          value="96.59%"
          color="#a78bfa"
        />
      </div>

      <div className="chart-grid">
        <section className="panel analytics-placeholder">
          <BarChart3 size={36} />

          <h2>Feature Importance</h2>

          <p>
            This section will retrieve Random Forest
            feature importance values from FastAPI.
          </p>
        </section>

        <section className="panel analytics-placeholder">
          <Activity size={36} />

          <h2>Confusion Matrix</h2>

          <p>
            This section will retrieve model evaluation
            results from FastAPI.
          </p>
        </section>
      </div>
    </>
  );
}


function SettingsPage() {
  return (
    <div className="settings-grid">
      <section className="panel">
        <h2>NVD Integration</h2>

        <p className="connected">
          ● API connection configured
        </p>

        <p>
          The NVD key will be stored securely by the
          FastAPI backend.
        </p>
      </section>

      <section className="panel">
        <h2>Machine Learning Model</h2>

        <dl>
          <div>
            <dt>Algorithm</dt>
            <dd>Random Forest Classifier</dd>
          </div>

          <div>
            <dt>Status</dt>
            <dd className="connected">Ready</dd>
          </div>
        </dl>
      </section>

      <section className="panel">
        <h2>Data Refresh</h2>

        <p>
          Fetch recent NVD data and recalculate
          priorities.
        </p>

        <button className="primary-button">
          <RefreshCw size={15} />
          Refresh NVD Data
        </button>
      </section>
    </div>
  );
}


export default function App() {
  const [activePage, setActivePage] =
    useState("dashboard");

  const [
    selectedVulnerability,
    setSelectedVulnerability,
  ] = useState(null);

  function openVulnerability(item) {
    setSelectedVulnerability(item);
    setActivePage("details");
  }

  function renderCurrentPage() {
    if (activePage === "details") {
      return (
        <VulnerabilityDetails
          vulnerability={selectedVulnerability}
          onBack={() =>
            setActivePage("vulnerabilities")
          }
        />
      );
    }

    if (activePage === "vulnerabilities") {
      return (
        <VulnerabilitiesPage
          data={vulnerabilities}
          onSelect={openVulnerability}
        />
      );
    }

    if (activePage === "analytics") {
      return <AnalyticsPage />;
    }

    if (activePage === "settings") {
      return <SettingsPage />;
    }

    return (
      <Dashboard
        data={vulnerabilities}
        onSelect={openVulnerability}
      />
    );
  }

  const pageTitle =
    activePage === "details"
      ? "Vulnerability Details"
      : navigation.find(
          (item) => item.id === activePage
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

            const active =
              activePage === item.id ||
              (activePage === "details" &&
                item.id === "vulnerabilities");

            return (
              <button
                key={item.id}
                className={
                  active
                    ? "nav-button active"
                    : "nav-button"
                }
                onClick={() =>
                  setActivePage(item.id)
                }
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
            <strong>NVD API</strong>
            <span>Backend pending</span>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <h1>{pageTitle}</h1>

            <p>
              Machine Learning-Based Vulnerability
              Prioritization
            </p>
          </div>

          <span className="online-indicator">
            ● FRONTEND ONLINE
          </span>
        </header>

        <div className="page">
          {renderCurrentPage()}
        </div>
      </main>
    </div>
  );
}