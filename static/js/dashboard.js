// Dashboard: pulls live data from /api/dashboard-data and renders
// stat cards, Chart.js charts, the recent-incidents table, the AI
// threat summary panel, and the attack timeline.

(function () {
  const SEV_COLORS = {
    Low: "#4ade80",
    Medium: "#fbbf24",
    High: "#fb7a3c",
    Critical: "#f43f5e",
  };

  const GRID_COLOR = "rgba(255,255,255,0.06)";
  const TEXT_COLOR = "#8a94ac";

  Chart.defaults.color = TEXT_COLOR;
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.borderColor = GRID_COLOR;

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function severityBadge(sev) {
    const cls = {
      Low: "badge-low",
      Medium: "badge-medium",
      High: "badge-high",
      Critical: "badge-critical",
    }[sev] || "badge-medium";
    return `<span class="badge-sev ${cls}">${escapeHtml(sev || "").toUpperCase()}</span>`;
  }

  function timeAgo(isoLike) {
    if (!isoLike) return "";
    const then = new Date(isoLike.replace(" ", "T") + "Z");
    const diffMs = Date.now() - then.getTime();
    const mins = Math.floor(diffMs / 60000);
    if (isNaN(mins)) return isoLike;
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  function renderCards(data) {
    document.getElementById("statTotalLogs").textContent = data.total_logs;
    document.getElementById("statThreats").textContent = data.threats_detected;
    document.getElementById("statCritical").textContent = data.severity_counts.Critical || 0;
    document.getElementById("statHigh").textContent = data.severity_counts.High || 0;
    document.getElementById("statMedium").textContent = data.severity_counts.Medium || 0;
    document.getElementById("statLow").textContent = data.severity_counts.Low || 0;
  }

  function renderPulseStrip(counts) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
    const strip = document.getElementById("pulseStrip");
    strip.innerHTML = `
      <span class="seg-low" style="width:${(counts.Low / total) * 100}%"></span>
      <span class="seg-medium" style="width:${(counts.Medium / total) * 100}%"></span>
      <span class="seg-high" style="width:${(counts.High / total) * 100}%"></span>
      <span class="seg-critical" style="width:${(counts.Critical / total) * 100}%"></span>
    `;
  }

  function renderSeverityChart(counts) {
    const ctx = document.getElementById("severityChart");
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Low", "Medium", "High", "Critical"],
        datasets: [{
          data: [counts.Low || 0, counts.Medium || 0, counts.High || 0, counts.Critical || 0],
          backgroundColor: [SEV_COLORS.Low, SEV_COLORS.Medium, SEV_COLORS.High, SEV_COLORS.Critical],
          borderColor: "#131b2e",
          borderWidth: 2,
        }],
      },
      options: {
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 12 } } },
        cutout: "62%",
      },
    });
  }

  function renderAttackTypeChart(attackCounts) {
    const ctx = document.getElementById("attackTypeChart");
    const labels = Object.keys(attackCounts);
    const values = Object.values(attackCounts);
    new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels.length ? labels : ["No data yet"],
        datasets: [{
          data: values.length ? values : [0],
          backgroundColor: "#22d3c8",
          borderRadius: 6,
          maxBarThickness: 34,
        }],
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: GRID_COLOR }, ticks: { precision: 0 } },
          y: { grid: { display: false } },
        },
      },
    });
  }

  function renderDailyChart(dailyCounts) {
    const ctx = document.getElementById("dailyChart");
    const labels = Object.keys(dailyCounts);
    const values = Object.values(dailyCounts);
    new Chart(ctx, {
      type: "line",
      data: {
        labels: labels.length ? labels : ["No data yet"],
        datasets: [{
          data: values.length ? values : [0],
          borderColor: "#22d3c8",
          backgroundColor: "rgba(34, 211, 200, 0.12)",
          fill: true,
          tension: 0.35,
          pointBackgroundColor: "#22d3c8",
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: GRID_COLOR }, ticks: { precision: 0 } },
        },
      },
    });
  }

  function renderRecentIncidents(incidents) {
    const tbody = document.getElementById("recentIncidentsBody");
    if (!incidents.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-muted small">No incidents yet. Upload and analyze a log file to get started.</td></tr>';
      return;
    }
    tbody.innerHTML = incidents.map((inc) => `
      <tr>
        <td class="mono small text-muted">${timeAgo(inc.created_at)}</td>
        <td class="small">${escapeHtml(inc.attack_type)}</td>
        <td class="ip-tag">${escapeHtml(inc.source_ip || "&mdash;")}</td>
        <td>${severityBadge(inc.severity)}</td>
      </tr>
    `).join("");
  }

  function renderAiSummary(incidents) {
    const panel = document.getElementById("aiSummaryPanel");
    if (!incidents.length) {
      panel.innerHTML = '<p class="text-muted small mb-0">No AI analysis yet. Once you analyze an uploaded file, the most notable finding will appear here.</p>';
      return;
    }
    // Prefer the highest-severity recent incident for the headline summary
    const order = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    const top = [...incidents].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0))[0];
    const recs = (top.recommendation || "").split(";").map((r) => r.trim()).filter(Boolean);

    panel.innerHTML = `
      <div class="d-flex align-items-center gap-2 mb-2">
        ${severityBadge(top.severity)}
        <span class="fw-semibold small">${escapeHtml(top.attack_type)}</span>
        <span class="badge-provider ms-auto">${escapeHtml(top.ai_provider || "simulated")}</span>
      </div>
      <p class="small mb-2" style="color: var(--text);">${escapeHtml(top.ai_summary)}</p>
      ${recs.length ? `<div class="small text-muted mb-1">Recommended mitigation:</div>
      <ul class="small mb-0" style="color: var(--text); padding-left: 1.1rem;">
        ${recs.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
      </ul>` : ""}
    `;
  }

  function renderTimeline(timeline) {
    const el = document.getElementById("attackTimeline");
    if (!timeline.length) {
      el.innerHTML = '<p class="text-muted small mb-0">No incidents recorded yet.</p>';
      return;
    }
    el.innerHTML = timeline.map((item) => `
      <div class="timeline-item sev-${(item.severity || "medium").toLowerCase()}">
        <div class="timeline-time">${escapeHtml(item.created_at)}</div>
        <div class="small">
          <span class="fw-semibold">${escapeHtml(item.attack_type)}</span>
          from <span class="ip-tag">${escapeHtml(item.source_ip || "unknown")}</span>
          ${severityBadge(item.severity)}
        </div>
      </div>
    `).join("");
  }

  async function loadDashboard() {
    try {
      const res = await fetch("/api/dashboard-data");
      const data = await res.json();

      renderCards(data);
      renderPulseStrip(data.severity_counts);
      renderSeverityChart(data.severity_counts);
      renderAttackTypeChart(data.attack_type_counts);
      renderDailyChart(data.daily_counts);
      renderRecentIncidents(data.recent_incidents);
      renderAiSummary(data.recent_incidents);
      renderTimeline(data.attack_timeline);
    } catch (err) {
      console.error("Failed to load dashboard data", err);
    }
  }

  loadDashboard();
})();
