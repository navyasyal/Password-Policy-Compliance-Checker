/* =====================================================================
   PolicyGuard :: dashboard.js
   Renders the charts, the findings table (search/sort/filter/mask),
   and the per-row Details modal. All of the underlying NUMBERS come
   from password_checker.py (via the JSON embedded by app.py) -- this
   file only decides how to draw them.
   ===================================================================== */

(function () {
  const raw = document.getElementById("scan-data");
  if (!raw) return; // dashboard.js is only used on the results page

  const scan = JSON.parse(raw.textContent);
  const report = scan.report || [];

  /* -------------------------------------------------------------
     Chart.js global theme (dark, security palette)
     ------------------------------------------------------------- */
  Chart.defaults.color = "#93a1b8";
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";

  const COLORS = {
    green: "#22c55e",
    red: "#ef4444",
    blue: "#3b82f6",
    cyan: "#22d3ee",
    amber: "#f59e0b",
    grid: "rgba(255,255,255,0.06)",
  };

  /* ---------------- Pie: Pass vs Fail ---------------- */
  new Chart(document.getElementById("passFailChart"), {
    type: "pie",
    data: {
      labels: ["Passed", "Failed"],
      datasets: [
        {
          data: [scan.passed, scan.failed],
          backgroundColor: [COLORS.green, COLORS.red],
          borderColor: "#0c1220",
          borderWidth: 2,
        },
      ],
    },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 16 } } },
    },
  });

  /* ---------------- Bar: Password Issues ---------------- */
  const issueBreakdown = scan.stats.issue_breakdown || {};
  const issueLabels = Object.keys(issueBreakdown);
  const issueValues = Object.values(issueBreakdown);

  new Chart(document.getElementById("issuesChart"), {
    type: "bar",
    data: {
      labels: issueLabels.length ? issueLabels : ["No Issues"],
      datasets: [
        {
          label: "Occurrences",
          data: issueValues.length ? issueValues : [0],
          backgroundColor: COLORS.blue,
          borderRadius: 6,
          maxBarThickness: 28,
        },
      ],
    },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { autoSkip: false, maxRotation: 30, minRotation: 0 } },
        y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: COLORS.grid } },
      },
    },
  });

  /* ---------------- Doughnut: Strength Distribution ---------------- */
  const dist = scan.stats.strength_distribution || { Strong: 0, Medium: 0, Weak: 0 };
  new Chart(document.getElementById("strengthChart"), {
    type: "doughnut",
    data: {
      labels: ["Strong", "Medium", "Weak"],
      datasets: [
        {
          data: [dist.Strong, dist.Medium, dist.Weak],
          backgroundColor: [COLORS.green, COLORS.amber, COLORS.red],
          borderColor: "#0c1220",
          borderWidth: 2,
        },
      ],
    },
    options: {
      maintainAspectRatio: false,
      cutout: "62%",
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 16 } } },
    },
  });

  /* -------------------------------------------------------------
     Findings table: render, search, sort, filter, mask, details
     ------------------------------------------------------------- */
  const tbody = document.getElementById("findingsBody");
  const noResults = document.getElementById("noResults");
  const searchInput = document.getElementById("searchInput");
  const filterButtons = document.querySelectorAll(".filter-btn");
  const maskToggle = document.getElementById("maskToggle");

  let currentFilter = "all";
  let currentSearch = "";
  let sortKey = null;
  let sortDir = 1; // 1 = asc, -1 = desc
  let allMasked = true;

  function badgeForStatus(status) {
    return status === "PASS"
      ? `<span class="badge-pill badge-pass"><i class="bi bi-check-lg"></i> PASS</span>`
      : `<span class="badge-pill badge-fail"><i class="bi bi-x-lg"></i> FAIL</span>`;
  }

  function badgeForLevel(level) {
    const cls = level === "Strong" ? "badge-strong" : level === "Medium" ? "badge-medium" : "badge-weak";
    return `<span class="badge-pill ${cls}">${level}</span>`;
  }

  function issuesHtml(issuesStr) {
    if (!issuesStr || issuesStr === "None") {
      return `<span class="issue-none">None</span>`;
    }
    return issuesStr
      .split(", ")
      .map((i) => `<span class="issue-tag">${escapeHtml(i)}</span>`)
      .join("");
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function maskPassword(pw) {
    return "&bull;".repeat(Math.min(pw.length, 14));
  }

  function passesFilter(row) {
    if (currentFilter === "pass" && row.Status !== "PASS") return false;
    if (currentFilter === "fail" && row.Status !== "FAIL") return false;
    if (currentFilter === "weak" && row["Strength Level"] !== "Weak") return false;
    return true;
  }

  function passesSearch(row) {
    if (!currentSearch) return true;
    const q = currentSearch.toLowerCase();
    return (
      row.Username.toLowerCase().includes(q) || row.Password.toLowerCase().includes(q)
    );
  }

  function getVisibleRows() {
    let rows = report.filter((r) => passesFilter(r) && passesSearch(r));
    if (sortKey) {
      rows = rows.slice().sort((a, b) => {
        const av = a[sortKey];
        const bv = b[sortKey];
        if (typeof av === "number" && typeof bv === "number") return (av - bv) * sortDir;
        return String(av).localeCompare(String(bv)) * sortDir;
      });
    }
    return rows;
  }

  function renderTable() {
    const rows = getVisibleRows();

    if (!rows.length) {
      tbody.innerHTML = "";
      noResults.classList.remove("d-none");
      return;
    }
    noResults.classList.add("d-none");

    tbody.innerHTML = rows
      .map((row, idx) => {
        const realIndex = report.indexOf(row);
        return `
          <tr>
            <td>${escapeHtml(row.Username)}</td>
            <td>
              <span class="cred-password">
                <span class="pw-text" data-pw="${escapeHtml(row.Password)}" data-masked="true">${maskPassword(row.Password)}</span>
                <i class="bi bi-eye pw-eye" data-row-toggle="${realIndex}" title="Show / hide password"></i>
              </span>
            </td>
            <td>${badgeForStatus(row.Status)}</td>
            <td class="mono">${row["Strength Score"]}</td>
            <td>${badgeForLevel(row["Strength Level"])}</td>
            <td>${issuesHtml(row.Issues)}</td>
            <td><button class="btn-details" data-details="${realIndex}"><i class="bi bi-info-circle"></i> Details</button></td>
          </tr>`;
      })
      .join("");
    // Note: per-row password reveal is wired via event delegation on
    // `tbody` below, since renderTable() re-creates these rows often.
  }

  renderTable();

  /* Search + filter listeners */
  searchInput.addEventListener("input", (e) => {
    currentSearch = e.target.value.trim();
    renderTable();
  });

  filterButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      renderTable();
    });
  });

  /* Column sorting */
  document.querySelectorAll(".findings-table th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      if (sortKey === key) {
        sortDir *= -1;
      } else {
        sortKey = key;
        sortDir = 1;
      }
      renderTable();
    });
  });

  /* Global mask/unmask toggle */
  maskToggle.addEventListener("click", () => {
    allMasked = !allMasked;
    maskToggle.innerHTML = allMasked
      ? `<i class="bi bi-eye-slash-fill"></i>`
      : `<i class="bi bi-eye-fill"></i>`;
    document.querySelectorAll(".pw-text").forEach((span) => {
      span.dataset.masked = allMasked ? "true" : "false";
      span.innerHTML = allMasked ? maskPassword(span.dataset.pw) : escapeHtml(span.dataset.pw);
      const eye = span.nextElementSibling;
      if (eye) eye.className = allMasked ? "bi bi-eye pw-eye" : "bi bi-eye-slash pw-eye";
    });
  });

  /* Per-row reveal via event delegation (table body is re-rendered often) */
  tbody.addEventListener("click", (e) => {
    const eye = e.target.closest(".pw-eye");
    if (eye) {
      const span = eye.previousElementSibling;
      const masked = span.dataset.masked !== "false";
      span.dataset.masked = masked ? "false" : "true";
      span.innerHTML = masked ? escapeHtml(span.dataset.pw) : maskPassword(span.dataset.pw);
      eye.className = masked ? "bi bi-eye-slash pw-eye" : "bi bi-eye pw-eye";
      eye.dataset.rowToggle = eye.dataset.rowToggle;
      return;
    }

    const detailsBtn = e.target.closest("[data-details]");
    if (detailsBtn) {
      const index = Number(detailsBtn.dataset.details);
      openDetails(report[index]);
    }
  });

  /* -------------------------------------------------------------
     Details modal: strength bar, issues, and recommendations
     ------------------------------------------------------------- */
  const RECOMMENDATIONS = {
    "Too Short": "Increase the password length to meet the configured minimum.",
    "Missing Uppercase": "Add at least one uppercase letter (A-Z).",
    "Missing Lowercase": "Add at least one lowercase letter (a-z).",
    "Missing Digit": "Add at least one numeric digit (0-9).",
    "Missing Special Character": "Add at least one special character (e.g. ! @ # $ %).",
    "Common Password": "Replace with a unique password not found in common password lists.",
    "Password Reused": "Assign a unique password; this one is shared with another account.",
  };

  function openDetails(row) {
    document.getElementById("modalUsername").textContent = row.Username;
    document.getElementById("modalStrengthScore").textContent = row["Strength Score"];
    document.getElementById("modalStrengthLevel").textContent = row["Strength Level"];

    const bar = document.getElementById("modalStrengthBar");
    bar.style.width = Math.min(row["Strength Score"], 100) + "%";
    bar.style.background =
      row["Strength Level"] === "Strong"
        ? COLORS.green
        : row["Strength Level"] === "Medium"
        ? COLORS.amber
        : COLORS.red;

    const issuesList = document.getElementById("modalIssues");
    const recsList = document.getElementById("modalRecs");

    if (!row.Issues || row.Issues === "None") {
      issuesList.innerHTML = `<li>No compliance issues found.</li>`;
      recsList.innerHTML = `<li>Password already meets policy requirements. No action needed.</li>`;
    } else {
      const issues = row.Issues.split(", ");
      issuesList.innerHTML = issues.map((i) => `<li>${escapeHtml(i)}</li>`).join("");
      recsList.innerHTML = issues
        .map((i) => `<li>${escapeHtml(RECOMMENDATIONS[i] || "Review this password against policy requirements.")}</li>`)
        .join("");
    }

    const modal = new bootstrap.Modal(document.getElementById("detailsModal"));
    modal.show();
  }
})();
