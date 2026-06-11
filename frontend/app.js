const API_URL = "http://127.0.0.1:8000";

let riskChart = null;
let searchedIds = [];

window.onload = function () {
    setupDarkMode();

    if (localStorage.getItem("loggedIn") === "true") {
        showDashboard();
    } else {
        showLogin();
    }
};

function showDashboard() {
    document.getElementById("loginPage").style.display = "none";
    document.getElementById("dashboard").style.display = "block";

    const name = localStorage.getItem("userName") || "Achal Gupta";
    document.getElementById("userProfile").innerText = "Welcome " + name;

    getStats();
    loadTopRisks();
    loadAll();
    refreshAttackGraph();
    loadAlerts();
    loadAssetRanking();
    loadBenchmark(); 
}

function showLogin() {
    document.getElementById("loginPage").style.display = "flex";
    document.getElementById("dashboard").style.display = "none";
}

function registerUser() {
    const name = document.getElementById("regName").value || "Achal Gupta";
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;
    const message = document.getElementById("loginMessage");

    if (!email || !password) {
        message.innerText = "Please enter email and password";
        return;
    }

    localStorage.setItem("userName", name);
    localStorage.setItem("userEmail", email);
    localStorage.setItem("userPassword", password);

    message.innerText = "Registered successfully. Click Login.";
}

function loginUser() {
    const name = document.getElementById("regName").value || "Achal Gupta";
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;
    const message = document.getElementById("loginMessage");

    if (!email || !password) {
        message.innerText = "Please enter email and password";
        return;
    }

    localStorage.setItem("loggedIn", "true");
    localStorage.setItem("userName", name);

    showDashboard();
}

function logoutUser() {
    localStorage.removeItem("loggedIn");

    document.getElementById("loginEmail").value = "";
    document.getElementById("loginPassword").value = "";
    document.getElementById("regName").value = "";
    document.getElementById("loginMessage").innerText = "Logged out successfully";

    showLogin();
}

function setupDarkMode() {
    const modeToggle = document.getElementById("modeToggle");

    if (!modeToggle) return;

    modeToggle.addEventListener("click", function () {
        document.body.classList.toggle("dark");

        if (document.body.classList.contains("dark")) {
            modeToggle.innerHTML = "Light mode";
        } else {
            modeToggle.innerHTML = "Dark mode";
        }
    });
}

async function getStats() {
    const response = await fetch(API_URL + "/dashboard");
    const data = await response.json();

    document.getElementById("total").innerText = data.total;
    document.getElementById("critical").innerText = data.critical;
    document.getElementById("high").innerText = data.high;
    document.getElementById("medium").innerText = data.medium;

    drawChart(data.critical, data.high, data.medium, data.low || 0);
}

function drawChart(critical, high, medium, low) {
    const ctx = document.getElementById("riskChart");

    if (riskChart) {
        riskChart.destroy();
    }

    riskChart = new Chart(ctx, {
        type: "pie",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: ["#7f1d1d", "#dc2626", "#f59e0b", "#16a34a"]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: "bottom"
                }
            }
        }
    });
}

async function loadTopRisks() {
    const response = await fetch(API_URL + "/top-risks");
    const data = await response.json();

    const list = document.getElementById("topRiskList");
    list.innerHTML = "";

    data.top_risks.forEach(function (vuln) {
        list.appendChild(createVulnCard(vuln));
    });
}

async function loadAll() {
    const response = await fetch(API_URL + "/vulnerabilities");
    const data = await response.json();

    const list = document.getElementById("vulnList");
    list.innerHTML = "";

    data.data.forEach(function (vuln) {
        const card = createVulnCard(vuln);

        if (searchedIds.includes(vuln.id)) {
            card.classList.add("result-highlight");
        }

        list.appendChild(card);
    });
}

function createVulnCard(vuln) {
    const div = document.createElement("div");
    div.className = "vuln-item";

    div.innerHTML =
        "<h3>" + vuln.vulnerability_name + "</h3>" +
        "<span class='badge " + vuln.severity + "'>" + vuln.severity + "</span>" +
        "<p><b>Asset:</b> " + vuln.asset + "</p>" +
        "<p><b>Port:</b> " + vuln.port + " | <b>Service:</b> " + vuln.service + "</p>" +
        "<p><b>CVE:</b> " + vuln.cve + " | <b>CVSS:</b> " + vuln.cvss_score + "</p>" +
        "<p><b>Source:</b> " + vuln.source_tool + "</p>" +
        "<p><b>Recommendation:</b> Patch service, restrict exposure, and monitor this asset.</p>";

    return div;
}

async function keywordSearch() {
    const query = document.getElementById("searchKeyword").value;

    if (!query) {
        alert("Enter search query");
        return;
    }

    const response = await fetch(API_URL + "/search?keyword=" + encodeURIComponent(query));
    const data = await response.json();

    searchedIds = data.results.map(function (item) {
        return item.id;
    });

    saveHistory("Keyword Search", query);
    showResult(data);
    renderSearchResults(data.results);
}

async function ragSearch() {
    const query = document.getElementById("ragQuery").value;

    if (!query) {
        alert("Enter AI search query");
        return;
    }

    const response = await fetch(API_URL + "/rag-search?question=" + encodeURIComponent(query));
    const data = await response.json();

    const results = data.results.map(function (item) {
        return item.vulnerability;
    });

    searchedIds = results.map(function (item) {
        return item.id;
    });

    saveHistory("RAG Search", query);
    showResult(data);
    renderSearchResults(results);
}

function renderSearchResults(results) {
    const list = document.getElementById("vulnList");
    list.innerHTML = "";

    results.forEach(function (vuln) {
        const card = createVulnCard(vuln);
        card.classList.add("result-highlight");
        list.appendChild(card);
    });
}

async function uploadJsonReport() {
    const fileInput = document.getElementById("jsonFile");
    const file = fileInput.files[0];

    if (!file) {
        alert("Please select JSON file");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(API_URL + "/upload-report", {
        method: "POST",
        body: formData
    });

    const data = await response.json();

    showResult(data);
    getStats();
    loadAll();
    loadTopRisks();

    fileInput.value = "";
}

async function uploadNmapXml() {
    const fileInput = document.getElementById("xmlFile");
    const file = fileInput.files[0];

    if (!file) {
        alert("Please select XML file");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(API_URL + "/upload-nmap-xml", {
        method: "POST",
        body: formData
    });

    const data = await response.json();

    showResult(data);
    getStats();
    loadAll();
    loadTopRisks();

    fileInput.value = "";
}

function refreshAttackGraph() {
    document.getElementById("attackGraph").src =
        API_URL + "/attack-graph?time=" + Date.now();
}

async function downloadJSONReport() {
    const response = await fetch(API_URL + "/vulnerabilities");
    const data = await response.json();

    const fileData = JSON.stringify(data.data, null, 2);
    const blob = new Blob([fileData], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "vulniq_report.json";
    a.click();

    URL.revokeObjectURL(url);
}

async function downloadPDFReport() {
    const response = await fetch(API_URL + "/vulnerabilities");
    const data = await response.json();

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    doc.setFontSize(18);
    doc.text("Vulniq Security Report", 20, 20);

    doc.setFontSize(11);
    doc.text("Centralized Vulnerability Detection and Intelligent Query Interface", 20, 30);

    let y = 45;

    data.data.forEach(function (vuln, index) {
        if (y > 260) {
            doc.addPage();
            y = 20;
        }

        doc.setFontSize(13);
        doc.text((index + 1) + ". " + vuln.vulnerability_name, 20, y);
        y += 8;

        doc.setFontSize(10);
        doc.text("Asset: " + vuln.asset, 25, y);
        y += 7;

        doc.text("Severity: " + vuln.severity + " | CVSS: " + vuln.cvss_score, 25, y);
        y += 7;

        doc.text("CVE: " + vuln.cve, 25, y);
        y += 10;
    });

    doc.save("vulniq_security_report.pdf");
}

function saveHistory(type, query) {
    let history = JSON.parse(localStorage.getItem("vulniqHistory")) || [];

    history.unshift({
        type: type,
        query: query,
        time: new Date().toLocaleString()
    });

    localStorage.setItem("vulniqHistory", JSON.stringify(history.slice(0, 15)));
    renderHistory();
}

function renderHistory() {
    const history = JSON.parse(localStorage.getItem("vulniqHistory")) || [];
    const box = document.getElementById("historyList");

    box.innerHTML = "";

    history.forEach(function (item) {
        box.innerHTML +=
            "<div class='history-item'>" +
            "<b>" + item.type + "</b><br>" +
            item.query + "<br>" +
            "<small>" + item.time + "</small>" +
            "</div>";
    });
}

function clearHistory() {
    localStorage.removeItem("vulniqHistory");
    renderHistory();
}

function showResult(data) {
    document.getElementById("result").textContent =
        JSON.stringify(data, null, 2);
}

setInterval(function () {
    if (localStorage.getItem("loggedIn") === "true") {
        getStats();
        loadTopRisks();
        loadAssetRanking();
        loadAlerts();
    }
}, 10000);
async function loadCVEFeed() {

    const response =
        await fetch(API_URL + "/cve-feed");

    const data =
        await response.json();

    const container =
        document.getElementById("cveContainer");

    container.innerHTML = "";

    data.results.forEach(cve => {

        container.innerHTML += `

        <div class="cve-card">

            <div class="cve-title">
                ${cve.cve_id}
            </div>

            <div class="cve-severity ${cve.severity}">
                ${cve.severity}
            </div>

            <p>${cve.description}</p>

            <p>
                <b>CVSS:</b>
                ${cve.cvss_score}
            </p>

            <p>
                <b>Recommendation:</b>
                ${cve.recommendation}
            </p>

        </div>

        `;
    });
}
async function loadExecutiveReport() {

    const response =
        await fetch(API_URL + "/executive-report");

    const data =
        await response.json();

    document.getElementById(
        "executiveReport"
    ).innerHTML = `

        <h3>Executive Security Summary</h3>

        <p>
            <b>Total Vulnerabilities:</b>
            ${data.total}
        </p>

        <p>
            <b>Critical:</b>
            ${data.critical}
        </p>

        <p>
            <b>High:</b>
            ${data.high}
        </p>

        <p>
            <b>Medium:</b>
            ${data.medium}
        </p>

        <p>
            <b>Most Dangerous Asset:</b>
            ${data.most_dangerous_asset}
        </p>

        <p>
            <b>Highest CVSS:</b>
            ${data.highest_cvss}
        </p>

        <p>
            <b>Top Vulnerability:</b>
            ${data.top_vulnerability}
        </p>

        <p>
            <b>Recommendation:</b>
            ${data.recommendation}
        </p>

    `;
}
async function loadMitreMapping() {

    const response =
        await fetch(API_URL + "/mitre-mapping");

    const data =
        await response.json();

    const container =
        document.getElementById("mitreContainer");

    container.innerHTML = "";

    data.results.forEach(item => {

        container.innerHTML += `

        <div class="mitre-card">

            <div class="mitre-title">
                ${item.vulnerability}
            </div>

            <p>
                <b>Asset:</b>
                ${item.asset}
            </p>

            <p>
                <b>Technique:</b>
                ${item.mitre.technique}
            </p>

            <p>
                <b>Name:</b>
                ${item.mitre.name}
            </p>

            <p>
                <b>Tactic:</b>
                ${item.mitre.tactic}
            </p>

        </div>

        `;
    });
}
async function loadRemediation() {

    const response =
        await fetch(API_URL + "/remediation");

    const data =
        await response.json();

    const container =
        document.getElementById(
            "remediationContainer"
        );

    container.innerHTML = "";

    data.results.forEach(item => {

        let fixes = "";

        item.recommendations.forEach(rec => {
            fixes += `<li>${rec}</li>`;
        });

        container.innerHTML += `

        <div class="remediation-card">

            <div class="remediation-title">
                ${item.vulnerability}
            </div>

            <p>
                <b>Asset:</b>
                ${item.asset}
            </p>

            <ul>
                ${fixes}
            </ul>

        </div>

        `;
    });
}
function refreshTopology() {

    document.getElementById(
        "networkTopology"
    ).src =
        API_URL +
        "/network-topology?time=" +
        Date.now();
}
async function startScan() {

    const target =
        document.getElementById(
            "scanTarget"
        ).value;

    if (!target) {
        alert("Enter target IP");
        return;
    }

    const response =
        await fetch(
            API_URL +
            "/nmap-scan?target=" +
            encodeURIComponent(target)
        );

    const data =
        await response.json();

    document.getElementById(
        "result"
    ).textContent =
        JSON.stringify(data, null, 2);

    getStats();
    loadAll();
    loadTopRisks();

    alert("Scan completed");
}
async function loadAlerts() {

    const response =
        await fetch(API_URL + "/alerts");

    const data =
        await response.json();

    const container =
        document.getElementById("alertContainer");

    container.innerHTML = "";

    if (data.count === 0) {

        container.innerHTML =
            "<p>No critical alerts.</p>";

        return;
    }

    data.alerts.forEach(alert => {

        const cssClass =
            alert.severity === "CRITICAL"
            ? "alert-critical"
            : "alert-high";

        container.innerHTML += `

        <div class="alert-card">

            <p class="${cssClass}">
                ${alert.severity}
            </p>

            <p>
                <b>Asset:</b>
                ${alert.asset}
            </p>

            <p>
                <b>Vulnerability:</b>
                ${alert.vulnerability}
            </p>

            <p>
                <b>CVSS:</b>
                ${alert.cvss_score}
            </p>

            <p>
                ${alert.message}
            </p>

        </div>

        `;
    });
}
async function loadAssetRanking() {

    const response =
        await fetch(API_URL + "/asset-ranking");

    const data =
        await response.json();

    const container =
        document.getElementById("assetRanking");

    container.innerHTML = "";

    data.results.forEach((item, index) => {

        container.innerHTML += `

        <div class="asset-card">

            <div class="asset-rank">
                #${index + 1}
            </div>

            <p>
                <b>Asset:</b>
                ${item.asset}
            </p>

            <p>
                <b>Risk Score:</b>
                ${item.risk_score}
            </p>

            <p>
                <b>Severity:</b>
                ${item.severity}
            </p>

            <p>
                <b>Vulnerability:</b>
                ${item.vulnerability}
            </p>

        </div>

        `;
    });
}
async function askCopilot() {

    const question =
        document.getElementById(
            "copilotQuestion"
        ).value;

    if (!question) {
        alert("Enter a question");
        return;
    }

    const response =
        await fetch(
            API_URL +
            "/ai-security-assistant?question=" +
            encodeURIComponent(question)
        );

    const data =
        await response.json();

    document.getElementById(
        "copilotAnswer"
    ).innerText =
        data.answer;
}
async function loadBenchmark() {

    const response =
        await fetch(
            API_URL +
            "/rag-benchmark?question=highest risk asset"
        );

    const data =
        await response.json();

    document.getElementById(
        "embeddingTime"
    ).innerText =
        data.benchmark.embedding_time_ms + " ms";

    document.getElementById(
        "searchTime"
    ).innerText =
        data.benchmark.search_time_ms + " ms";

    document.getElementById(
        "totalTime"
    ).innerText =
        data.benchmark.total_time_ms + " ms";

    document.getElementById(
        "recordCount"
    ).innerText =
        data.benchmark.records_processed;
}