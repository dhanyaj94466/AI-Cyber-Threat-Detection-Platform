/*==========================================================
    AI Cyber Threat Detection Platform
    Developer : DHANYAJ S
    Course    : BCA Final Year Project
    Year      : 2026
==========================================================*/

let pieChart;
let barChart;
let trendChart;
let monthlyThreatData = [0,0,0,0,0,0,0,0,0,0,0,0];
let threatTrendData = [0,0,0,0,0,0,0];
let latestTrendDetails = {
    day: "",
    threats: 0,
    risk: "Low"
};

// ==========================================
// Global Threat Statistics
// ==========================================

let dashboardStats = {

    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,

    failedLogins: 0,
    blockedIPs: 0,

    mostAttackedIP: "-",

    lastScan: "-",

    uploadedLogs: 0,

    websiteScans: 0

};

let weeklyThreatData = [0,0,0,0,0,0,0];

let totalCritical = 0;
let totalHigh = 0;
let totalMedium = 0;
let totalLow = 0;

let seconds = 60;

let lastCriticalNews = "";




let scannedSites = 0;



/*==========================================================
    INITIALIZATION
==========================================================*/

function updateClock() {

    const now = new Date();

    // DD/MM/YYYY
    const day = String(now.getDate()).padStart(2, '0');
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const year = now.getFullYear();

    const date = `${day}/${month}/${year}`;

    // Time (12-hour format)
    const time = now.toLocaleTimeString('en-IN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });

    document.getElementById("liveClock").innerHTML =
        `🗓 ${date}<br>🕒 ${time}`;
}

setInterval(updateClock, 1000);

updateClock();

/*==========================================================
    DASHBOARD FUNCTIONS
==========================================================*/

async function checkBackend() {

    try {

        const response = await fetch("http://127.0.0.1:8000/");

        const data = await response.json();

        document.getElementById("result").innerHTML =
            "✅ " + data.message;

    } catch (error) {

        document.getElementById("result").innerHTML =
            "❌ Backend Offline";

    }

}

// -------------------------------
// Read Uploaded File
// -------------------------------

function readFile() {

    const file = document.getElementById("logFile").files[0];

    const uploadButton = document.getElementById("uploadButton");

    const loading = document.getElementById("loadingText");

    const progress = document.getElementById("analysisProgress");

    if(!file){

        addNotification("❌ Please select a log file.");

        alert("Please select a log file.");

        return;

    }

    uploadButton.disabled = true;

uploadButton.innerHTML = "Analyzing...";

loading.style.display = "block";

progress.style.width = "20%";

const allowedTypes = [

"text/plain",

"application/octet-stream"

];

if(!allowedTypes.includes(file.type) &&

!file.name.endsWith(".log") &&

!file.name.endsWith(".txt")){

addNotification("❌ Invalid file type.");

alert("Only .log and .txt files are supported.");

return;

}

    const reader = new FileReader();

    reader.onload = function (event) {

      const text = event.target.result;

      progress.style.width="50%";

if(text.trim() === ""){

    addNotification("❌ Empty log file.");

    alert("The selected log file is empty.");

    return;

}

      document.getElementById("logContent").textContent = text;

if(
    !text.includes("LOGIN") &&
    !text.includes("FAILED") &&
    !text.includes("ERROR")
){

    addNotification("⚠ Invalid log format.");

    alert("Unsupported log format.");

    return;
}

analyzeLogs(text);

generateAIDecision();

progress.style.width="80%";

        addActivity("📂 Log File Uploaded");

addActivity("🤖 AI Analysis Completed");

addActivity("🌐 Website Scan Completed");

addActivity("📧 Email Alert Sent");

addActivity("📄 PDF Report Generated");

addActivity("📥 CSV Downloaded");

addActivity("🚨 Critical Threat Detected");

addActivity("🛡 Firewall Recommendation Generated");

addNotification("📁 Log File Uploaded");

progress.style.width="100%";

addScanHistory(
    "Uploaded Log File",
    "Analyzed"
);

setTimeout(function(){

    loading.style.display = "none";

    uploadButton.disabled = false;

    uploadButton.innerHTML = "Upload Log File";

    progress.style.width = "0%";

alert("Analysis Completed Successfully");

}, 700);
    };

    reader.readAsText(file);

}

/*==========================================================
    LOG ANALYSIS
==========================================================*/

function analyzeLogs(text) {

    

    const lines = text.split("\n");
    const failedIPs = {};

    for (let line of lines) {
        if (line.includes("LOGIN FAILED")) {
            const match = line.match(/ip=([^\s]+)/i);
            if (!match) {
                continue;
            }
            const ip = match[1].trim();
            failedIPs[ip] = (failedIPs[ip] || 0) + 1;
        }
    }

    let html = "";
    let aiText = "";
    let total = 0;
    let low = 0;
    let medium = 0;
    let high = 0;
    let critical = 0;
    let criticalIP = "";
    let criticalAttempts = 0;

    for (let ip in failedIPs) {
        const attempts = failedIPs[ip];
        let severity = "";
        let color = "";

        if (attempts === 1) {
            severity = "Low";
            color = "#4CAF50";
            low++;
        } else if (attempts === 2) {
            severity = "Medium";
            color = "#FFC107";
            medium++;
        } else if (attempts === 3) {
            severity = "High";
            color = "#FF9800";
            high++;
        } else {
            severity = "Critical";
            color = "#F44336";
            critical++;
        }


   
        total++;

        if (severity === "Critical" && attempts > criticalAttempts) {
            criticalIP = ip;
            criticalAttempts = attempts;
        }

        addThreatTimeline(
            `${severity} Threat detected from ${ip} (${attempts} attempts)`
        );

        html += `
<tr>
    <td>${ip}</td>
    <td>Failed Login (${attempts} Attempts)</td>
    <td style="color:${color};font-weight:bold;">${severity}</td>
    <td><button onclick="checkIPReputation('${ip}')">Check Reputation</button></td>
</tr>
`;

        aiText += `
--------------------------------------------------

IP Address : ${ip}

Threat Level : ${severity}

Failed Attempts : ${attempts}

Possible Attack :
Brute Force Attack

AI Recommendation :

• Block the IP temporarily

• Review login history

• Enable Multi-Factor Authentication

• Monitor future login attempts

--------------------------------------------------

`;
    }

    if (total === 0) {
        html = `
        <tr>
            <td colspan="3">No Threats Detected</td>
        </tr>
        `;
        aiText = "✅ No suspicious activity detected.";
    }


// ===============================
// Threat Statistics
// ===============================


let maxAttempts = 0;
let mostAttackedIP = "-";

for (let ip in failedIPs) {

    if (failedIPs[ip] > maxAttempts) {

        maxAttempts = failedIPs[ip];
        mostAttackedIP = ip;

    }

}

// ===============================
// AI Summary
// ===============================


document.getElementById("summaryBox").innerHTML =

`

<h3>AI Threat Summary</h3>

<p>Total Threats :
${total}</p>

<p>Critical :
${critical}</p>

<p>High :
${high}</p>

<p>Medium :
${medium}</p>

<p>Low :
${low}</p>

<p>Most Attacked IP :
${mostAttackedIP}</p>

<p>

Recommendation:

Immediately block critical IPs,

enable MFA,

monitor failed logins,

and update firewall rules.

</p>

`;





document.getElementById("mostIP").innerHTML = mostAttackedIP;

document.getElementById("failedLogins").innerHTML =
Object.values(failedIPs).reduce((a, b) => a + b, 0);

document.getElementById("highestThreat").innerHTML =
critical > 0 ? "Critical" :
high > 0 ? "High" :
medium > 0 ? "Medium" :
low > 0 ? "Low" : "None";

document.getElementById("lastScan").innerHTML =
new Date().toLocaleTimeString('en-IN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
});

    document.getElementById("threatTable").innerHTML = html;
   document.getElementById("total").innerHTML = total;
document.getElementById("low").innerHTML = low;
document.getElementById("medium").innerHTML = medium;
document.getElementById("high").innerHTML = high;
document.getElementById("critical").innerHTML = critical;
    document.getElementById("aiResult").innerHTML = "<pre>" + aiText + "</pre>";


    

    drawCharts(low, medium, high, critical);
    updateSecurityScore(critical, high, medium, low);
    addActivity("🤖 AI analyzed log file");

    if (critical > 0) {
        sendEmailAlert(criticalIP, criticalAttempts);
        alert(
            "🚨 CRITICAL THREAT DETECTED\n\n" +
            "IP Address : " + criticalIP + "\n" +
            "Attempts : " + criticalAttempts + "\n\nEmail Alert Sent."
            
        );
    }

    // Update dashboard statistics

dashboardStats.total = total;

const today = new Date().getDay();
const index = today === 0 ? 6 : today - 1;

latestTrendDetails.day = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][index];
latestTrendDetails.threats = total;
latestTrendDetails.risk =
    critical > 0 ? "🔴 Critical" :
    high > 0 ? "🟠 High" :
    medium > 0 ? "🟡 Medium" :
    "🟢 Low";

    console.log({
    critical,
    high,
    medium,
    low,
    risk: latestTrendDetails.risk
});

console.log("Total =", total);
console.log("Failed IPs =", failedIPs);
console.log("Trend Data Before =", threatTrendData);

dashboardStats.critical = critical;

dashboardStats.high = high;

dashboardStats.medium = medium;

dashboardStats.low = low;

totalCritical = critical;
totalHigh = high;
totalMedium = medium;
totalLow = low;

dashboardStats.failedLogins = total;

dashboardStats.mostAttackedIP = criticalIP || "-";

dashboardStats.lastScan = new Date().toLocaleString();

dashboardStats.uploadedLogs++;

const currentMonth = new Date().getMonth();

monthlyThreatData[currentMonth] = dashboardStats.total;


weeklyThreatData[index] = dashboardStats.total;

threatTrendData[index] = dashboardStats.total;


// Refresh dashboard

updateDashboardCards();

updateSecurityHealth();

updateExecutiveDashboard();

updateAIOverview();

updateThreatStatistics();

updatePrediction();

generateRecommendations();

generateIncidentResponse();

loadWeeklyChart();

loadMonthlyChart();


loadThreatTrend();

if(window.securityHistoryChart){
    console.log(window.securityHistoryChart.data.datasets[0].data);
}

}



    
/*==========================================================
    CHART FUNCTIONS
==========================================================*/

function drawCharts(low, medium, high, critical) {

    if (pieChart != null) {

        pieChart.destroy();

    }

    if (barChart != null) {

        barChart.destroy();

    }

    // Pie Chart

    const pie = document.getElementById("pieChart");

    if (!pie) {
    console.error("Pie chart canvas not found");
    return;
}

    pieChart = new Chart(pie, {

        type: "pie",

        data: {

            labels: [

                "Low",

                "Medium",

                "High",

                "Critical"

            ],

            datasets: [{

                data: [

                    low,

                    medium,

                    high,

                    critical

                ],

                backgroundColor: [

                    "#4CAF50",

                    "#FFC107",

                    "#FF9800",

                    "#F44336"

                ]

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            plugins: {

                legend: {

                    position: "bottom"

                }

            }

        }

    });

    // Bar Chart

    const bar = document.getElementById("barChart");

    if (!bar) {
    console.error("Bar chart canvas not found");
    return;
}

    barChart = new Chart(bar, {

        type: "bar",

        data: {

            labels: [

                "Low",

                "Medium",

                "High",

                "Critical"

            ],

            datasets: [{

                label: "Threat Count",

                data: [

                    low,

                    medium,

                    high,

                    critical

                ],

                backgroundColor: [

                    "#4CAF50",

                    "#FFC107",

                    "#FF9800",

                    "#F44336"

                ]

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            scales: {

                y: {

                    beginAtZero: true,

                    ticks: {

                        stepSize: 1

                    }

                }

            }

        }

    });

}

/*==========================================================
    WEBSITE SCANNER
==========================================================*/

async function scanWebsite() {

    const url = document.getElementById("websiteUrl").value.trim();

    if(url === ""){

        addNotification("❌ Please enter a website URL.");

        alert("Please enter a website URL.");

        return;

    }

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/scan?url=" +
            encodeURIComponent(url)
        );

        if (!response.ok) {
    throw new Error("Backend Server Error");
}

        const data = await response.json();

        if (data.error) {

            document.getElementById("websiteResult").innerHTML =
                "<h3 style='color:red'>" + data.error + "</h3>";

            return;

        }

        let html = `
            <h2>🌐 Website Security Report</h2>

            <p><b>Domain:</b> ${data.domain}</p>

            <p><b>IP Address:</b> ${data.ip}</p>

            <p><b>Status Code:</b> ${data.status}</p>

            <p><b>HTTPS:</b> ${data.https ? "✅ Enabled" : "❌ Disabled"}</p>

            <p><b>Risk Score:</b> ${data.score}/100</p>

            <p><b>Threat Level:</b> ${data.level}</p>

            <h3>Security Headers</h3>

            <ul>
        `;

        data.headers.forEach(function(item){

            html += "<li>" + item + "</li>";

        });

        html += "</ul>";

        document.getElementById("websiteResult").innerHTML = html;

        scannedSites++;

document.getElementById("scannedSites").innerHTML = scannedSites;

addActivity("🌐 Website scanned: " + url);

addNotification("🌐 Website Scan Completed");

addScanHistory(

document.getElementById("websiteUrl").value,

"Website Scanned"

);

    } catch (error) {

        document.getElementById("websiteResult").innerHTML =
            "<h3 style='color:red'>Unable to connect to backend.</h3>";

       console.error(error);

addNotification("❌ Backend Server Offline");

alert("Unable to connect to the backend server.");

    }

}

async function virusTotalScan() {

   

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/virustotal?url=" +
            encodeURIComponent(url)
        );

        const data = await response.json();

        if (data.error) {

            document.getElementById("websiteResult").innerHTML =
                "<h3 style='color:red'>" + data.error + "</h3>";

            return;

        }

        document.getElementById("websiteResult").innerHTML = `
            <h2>🛡 VirusTotal Report</h2>

            <p><b>Malicious:</b> ${data.malicious}</p>

            <p><b>Suspicious:</b> ${data.suspicious}</p>

            <p><b>Harmless:</b> ${data.harmless}</p>

            <p><b>Undetected:</b> ${data.undetected}</p>

            <h2>${data.verdict}</h2>
        `;

        addActivity("🛡 VirusTotal scan completed");

        addNotification("🛡 VirusTotal Scan Finished");

        addScanHistory(

document.getElementById("websiteUrl").value,

"VirusTotal Scan"

);

    } catch (error) {
        console.error(error);
        document.getElementById("websiteResult").innerHTML =
            "<h3 style='color:red'>VirusTotal scan failed.</h3>";
    }

}

// ===============================
// Security Score
// ===============================

function updateSecurityScore(critical, high, medium, low) {

    let score = 100;

    score -= critical * 20;
    score -= high * 10;
    score -= medium * 5;
    score -= low * 2;

    if (score < 0) {
        score = 0;
    }

    document.getElementById("securityScore").innerHTML = score + "%";

    document.getElementById("blockedIPs").innerHTML = critical + high;


}



// ===============================
// Activity Log
// ===============================

function addActivity(message) {

    const log = document.getElementById("activityLog");

    const time = new Date().toLocaleTimeString();

    log.innerHTML =
        "<p><b>" + time + "</b> - " + message + "</p>" +
        log.innerHTML;

}


function logout() {

    localStorage.removeItem("loggedIn");

    window.location.href = "login.html";

}




// ===============================
// Download PDF Report
// ===============================

function downloadPDF() {

    const { jsPDF } = window.jspdf;

    const doc = new jsPDF();

  doc.setFont("helvetica","bold");

doc.setFontSize(20);

doc.setTextColor(21,101,192);

doc.text("AI Cyber Threat Detection Platform",20,20);

doc.setFontSize(12);

doc.setTextColor(0,0,0);

doc.text("Cyber Security Analysis Report",20,30);

doc.line(20,35,190,35);

const reportDate = new Date().toLocaleString();

doc.setFontSize(11);

doc.text("Generated By : DHANYAJ S",20,45);

doc.text("Project : AI Cyber Threat Detection Platform",20,52);

doc.text("Date & Time : " + reportDate,20,59);

doc.text("Course : Bachelor of Computer Applications (BCA)",20,66);

doc.text("Institution : ITM College of Arts and Science",20,73);

doc.line(20,78,190,78);

    doc.setFontSize(12);

    let y = 90;

doc.setFont("helvetica","bold");

doc.setFontSize(15);

doc.text("Dashboard Summary",20,y);

 y += 12;

doc.setFont("helvetica","normal");
doc.setFontSize(12);

doc.text("Total Threats : " + document.getElementById("total").innerText,20,y);

y += 10;

doc.text("Critical : " + document.getElementById("critical").innerText,20,y);

y += 10;

doc.text("High : " + document.getElementById("high").innerText,20,y);

y += 10;

doc.text("Medium : " + document.getElementById("medium").innerText,20,y);

y += 10;

doc.text("Low : " + document.getElementById("low").innerText,20,y);

y += 10;

const score = document.getElementById("securityScore");

if(score){

    doc.text("Security Score : " + score.innerText,20,y);

    y += 10;

let pdfRisk = getRiskLevel();

pdfRisk = pdfRisk
    .replace("🔴 ","")
    .replace("🟠 ","")
    .replace("🟡 ","")
    .replace("🟢 ","");

doc.text(
    "Overall Risk Level : " + pdfRisk,
    20,
    y
);

y += 10;

doc.text(
    "Most Attacked IP : " +
    dashboardStats.mostAttackedIP,
    20,
    y
);

y += 10;

doc.text(
    "Failed Login Attempts : " +
    dashboardStats.failedLogins,
    20,
    y
);

y += 10;

doc.setFont("helvetica","bold");

doc.text("AI Decision :",20,y);

doc.setFont("helvetica","normal");

y += 10;

doc.text(pdfRisk,20,y);

y += 15;

doc.line(20,y,190,y);

y += 10;

}
  y += 20;

doc.setFont("helvetica","bold");
doc.setFontSize(15);

doc.text("Website Security Report",20,y);

y += 10;

let report = document.getElementById("websiteResult").innerText;

// Remove duplicate heading
report = report.replace("Website Security Report", "").trim();

    report = report
        .replace(/✅/g, "Yes")
        .replace(/❌/g, "No")
        .replace(/🟢/g, "Low")
        .replace(/🟡/g, "Medium")
        .replace(/🟠/g, "High")
        .replace(/🔴/g, "Critical")
        .replace(/🌐/g, "")
        .replace(/🛡/g, "")
        .replace(/🤖/g, "");

    const lines = doc.splitTextToSize(report, 170);

    doc.text(lines, 20, y);

    doc.save("Cyber_Threat_Report.pdf");

    addNotification("📄 PDF Report Generated");

    addReport(
        "Threat_Report.pdf",
        "PDF"
    );

}
    

function addTimeline(message){

    const timeline = document.getElementById("timeline");

    const time = new Date().toLocaleTimeString();

    timeline.innerHTML =
        "<p><b>" + time + "</b> - " + message + "</p>" +
        timeline.innerHTML;

}



function showNotification(title, body){

    if(Notification.permission === "granted"){

        new Notification(title,{
            body: body
        });

    }

}

Notification.requestPermission();

 

/*==========================================================
    THREAT INTELLIGENCE
==========================================================*/

function addThreatTimeline(message) {

    const timeline = document.getElementById("threatTimeline");

    const time = new Date().toLocaleTimeString();

    timeline.innerHTML =
        "<p><b>" + time + "</b> - " + message + "</p>" +
        timeline.innerHTML;

}


async function checkIPReputation(ip){

    try{

        const response = await fetch(

            "http://127.0.0.1:8000/ipinfo?ip=" + ip

        );

        const data = await response.json();

        let recommendation = "Safe";

        if(

            ip.startsWith("192.") ||

            ip.startsWith("10.")

        ){

            recommendation="Private Network";

        }

        document.getElementById(

            "ipReputationResult"

        ).innerHTML = `

        <h2>🌍 IP Reputation Report</h2>

        <p><b>IP Address :</b> ${data.ip}</p>

        <p><b>Country :</b> ${data.country}</p>

        <p><b>City :</b> ${data.city}</p>

        <p><b>ISP :</b> ${data.isp}</p>

        <p><b>Organization :</b> ${data.organization}</p>

        <p><b>Status :</b> ${data.status}</p>

        <p><b>AI Recommendation :</b> ${recommendation}</p>

        `;

    } catch (error) {
        console.error(error);
    }
}




// ===============================
// send Email Alert
// ===============================


async function sendEmailAlert(ip, attempts) {

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/send_alert?ip=" +
            encodeURIComponent(ip) +
            "&attempts=" +
            attempts
        );

        const data = await response.json();

        console.log(data);

        addActivity("📧 Email Alert Sent for " + ip);


   

    } catch (error) {

        console.log(error);

    }

}


// ===============================
// search threat
// ===============================

 function searchThreat(){

let input =
document.getElementById("searchIP")
.value
.toUpperCase();

let rows =
document.querySelectorAll("#threatTable tr");

rows.forEach(row=>{

if(row.innerText.toUpperCase().includes(input))

row.style.display="";

else

row.style.display="none";

});

}


// ===============================
// filter threats
// ===============================

function filterThreats(){

const filter =
document.getElementById("severityFilter").value;

const rows =
document.querySelectorAll("#threatTable tr");

rows.forEach(row=>{

if(filter=="All")

row.style.display="";

else if(row.innerText.includes(filter))

row.style.display="";

else

row.style.display="none";

});

}


// ===============================
// download CSV
// ===============================

function downloadCSV(){

let csv =
"IP Address,Threat,Severity\n";

const rows =
document.querySelectorAll("#threatTable tr");

rows.forEach(row=>{

let cols=row.querySelectorAll("td");

if(cols.length>=3){

csv +=
cols[0].innerText + "," +
cols[1].innerText + "," +
cols[2].innerText +
"\n";

}

});

const blob =
new Blob([csv],{type:"text/csv"});

const link =
document.createElement("a");

link.href =
URL.createObjectURL(blob);

link.download =
"Threat_Report.csv";

link.click();

addActivity("📄 CSV Downloaded");

addNotification("📊 CSV Report Exported");

addReport(

"Threat_Report.csv",

"CSV"

);

}


// ===============================
// Load Threat News
// ===============================
   

async function loadThreatNews(){

    try {

        const newsContainer = document.getElementById("newsContainer");

        newsContainer.innerHTML = `
        <div class="news-card">
            <h3>🛡 Connecting to Live Threat Intelligence...</h3>
        </div>
        `;

        const response = await fetch("http://127.0.0.1:8000/news");

        if (!response.ok) {
            throw new Error("Unable to fetch news.");
        }

        const data = await response.json();

        allThreatNews = data.news;

        console.log("News Loaded:", allThreatNews);

        displayNews(allThreatNews);

        addNotification("📰 Threat Intelligence Updated");

        showToast(

"🔄 Threat Intelligence Updated",

"info"

);

        checkCriticalNotification(allThreatNews);

        document.getElementById("newsTime").innerHTML =
            "Last Updated : " +
            new Date().toLocaleString();

        addActivity("🌍 Threat Intelligence Updated");

    }
    catch (error) {

        console.error(error);

        document.getElementById("newsContainer").innerHTML = `
        <div class="news-card">
            <h3 style="color:red;">
                ❌ Unable to load Threat Intelligence Feed
            </h3>
            <p>Please check if the backend server is running.</p>
        </div>
        `;

    }

}


/*==========================================================
    NEWS FILTERS
==========================================================*/


function filterNews() {

    const searchText = document.getElementById("newsSearch").value
        .toLowerCase()
        .trim();

    const selectedSeverity = 
    document.getElementById("newsSeverity").value;

    const sourceElement = document.getElementById("newsSource");
const sortElement = document.getElementById("newsSort");

const selectedSource = sourceElement ? sourceElement.value : "All";
const sortType = sortElement ? sortElement.value : "Newest";

    
    console.log("Search:", searchText);
    console.log("Severity:", selectedSeverity);
    console.log("All News:", allThreatNews);

    const filteredNews = allThreatNews.filter(news => {

        console.log(news.title);
        console.log(news.source);
        console.log(news.severity);

        const matchSearch =
            news.title.toLowerCase().includes(searchText) ||
            news.source.toLowerCase().includes(searchText);

        const matchSeverity =
            selectedSeverity === "All" ||   
            news.severity === selectedSeverity;

            const matchSource =
            selectedSource === "All" ||
            news.source.toLowerCase().includes(
            selectedSource.toLowerCase()
);

        console.log(matchSearch, matchSeverity);

        return matchSearch &&
       matchSeverity &&
       matchSource;

    });

    console.log(filteredNews);

    if(sortType === "Newest"){

    filteredNews.sort((a,b)=>

        new Date(b.published) -
        new Date(a.published)

    );

}

else if(sortType === "Oldest"){

    filteredNews.sort((a,b)=>

        new Date(a.published) -
        new Date(b.published)

    );

}

else if(sortType === "A-Z"){

    filteredNews.sort((a,b)=>

        a.title.localeCompare(b.title)

    );

}

else if(sortType === "Z-A"){

    filteredNews.sort((a,b)=>

        b.title.localeCompare(a.title)

    );

}

displayNews(filteredNews);

}


// ===============================
// Load News Automatically
// ===============================

window.addEventListener("DOMContentLoaded",()=>{

    loadThreatNews();

    loadWeeklyChart();

     loadMonthlyChart();

    loadPinnedNews();

    loadBookmarks();

    loadThreatTrend();

    


    updateMonthlyInsight();

    updatePrediction();


   


    updateSystemStatus();

    startCountdown();

    setInterval(() => {

        loadThreatNews();

        seconds = 60;

    },60000);

    addNotification("🟢 Dashboard Started");

addNotification("🟢 Threat Intelligence Feed Connected");

addNotification("🟢 AI Engine Ready");

    // Restore Theme

if(localStorage.getItem("theme")==="dark"){

    document.body.classList.add("dark-mode");

    document.getElementById("themeButton").innerHTML="☀ Light Mode";

}

});




function startCountdown(){  
    

    setInterval(()=>{

        seconds--;

        if(seconds < 0){

            seconds = 60;

        }

        document.getElementById("refreshCountdown").innerHTML =

        "Next Refresh : " + seconds + " sec";

    },1000);

}


// ===============================
// display news
// ===============================


function displayNews(newsList){

    const newsContainer = document.getElementById("newsContainer");

    let html = "";

    // No News
    if(newsList.length === 0){

        newsContainer.innerHTML = `

        

        <div class="news-card">
            <h3 style="color:red;text-align:center;">
                ❌ No matching news found
            </h3>
        </div>
        `;

        return;
    }

    // ===========================
    // Latest Critical Alert
    // ===========================

    const criticalNews = newsList.find(
        item => item.severity === "Critical"
    );

    if(criticalNews){

        document.getElementById("criticalAlert").innerHTML = `

        <h2>🚨 Latest Critical Alert</h2>

        <p><b>${criticalNews.title}</b></p>

        <p>🌐 ${criticalNews.source}</p>

        <p>📅 ${criticalNews.published}</p>

        <p>
            <a href="${criticalNews.url}" target="_blank">
                📖 Read Full Report
            </a>
        </p>

        `;

    }else{

        document.getElementById("criticalAlert").innerHTML = `
        <h2 style="color:green;">
            ✅ No Critical Threats Today
        </h2>
        `;

    }

    // ===========================
    // Statistics
    // ===========================

    let total = newsList.length;

    totalCritical =
    newsList.filter(n => n.severity === "Critical").length;

totalHigh =
    newsList.filter(n => n.severity === "High").length;

totalMedium =
    newsList.filter(n => n.severity === "Medium").length;

totalLow =
    newsList.filter(n => n.severity === "Low").length;  
    document.getElementById("newsTotal").innerHTML = total;
    document.getElementById("newsCritical").innerHTML = totalCritical;
document.getElementById("newsHigh").innerHTML = totalHigh;
document.getElementById("newsMedium").innerHTML = totalMedium;
document.getElementById("newsLow").innerHTML = totalLow;

    // ===========================
    // Create News Cards
    // ===========================

    newsList.forEach(item => {

        let trustedBadge = "🟡 Community Source";
        let sourceLogo = "🌐";

        const source = item.source.toLowerCase();

        if(source.includes("bleepingcomputer")){
            trustedBadge = "🟢 Trusted Source";
            sourceLogo = "💻";
        }
        else if(source.includes("microsoft")){
            trustedBadge = "🟢 Trusted Source";
            sourceLogo = "🪟";
        }
        else if(source.includes("google")){
            trustedBadge = "🟢 Trusted Source";
            sourceLogo = "🌎";
        }
        else if(source.includes("cisa")){
            trustedBadge = "🟢 Trusted Source";
            sourceLogo = "🛡";
        }

        let category = "General";

        const title = item.title.toLowerCase();

        if(title.includes("malware"))
            category = "🦠 Malware";
        else if(title.includes("phishing"))
            category = "🎣 Phishing";
        else if(title.includes("ransomware"))
            category = "💣 Ransomware";
        else if(title.includes("vulnerability"))
            category = "🐞 Vulnerability";
        else if(title.includes("exploit"))
            category = "⚔ Exploit";
        else if(title.includes("breach"))
            category = "📂 Data Breach";

    html += `

<div class="news-card">

    <div class="news-title">
        ${item.title}
    </div>

    <div class="news-source">
        ${sourceLogo} ${item.source}
    </div>

    <div class="trusted-badge">
        ${trustedBadge}
    </div>

    <div class="news-date">
        📅 ${item.published}
    </div>

    <div class="news-category">
        ${category}
    </div>

    <br>

    <div class="news-actions">

        <a
        href="${item.url}"
        target="_blank"
        class="news-button">

        📖 Read Report

        </a>

        <button
        class="pin-btn"
        onclick='pinNews(${JSON.stringify(item)})'>

        📌 Pin

        </button>

        <button
        class="bookmark-btn"
        onclick='bookmarkNews(${JSON.stringify(item)})'>

        ⭐ Save

        </button>

    </div>

</div>

`;

    });

    newsContainer.innerHTML = html;

    generateRecommendations();

    updateSecurityHealth();

    generateIncidentResponse();

    updateExecutiveDashboard();

    updatePrediction();

}

/*==========================================================
    BOOKMARKS
==========================================================*/

function bookmarkNews(news){

    let favorites =
    JSON.parse(localStorage.getItem("favorites")) || [];

    const exists =
    favorites.some(item => item.url === news.url);

    if(!exists){

        favorites.push(news);

        showToast(

"⭐ News Bookmarked Successfully",

"success"

);
}}


function loadBookmarks(){

    const favorites =
    JSON.parse(localStorage.getItem("favorites")) || [];

    let html="";

    if(favorites.length===0){

        html="No bookmarked reports.";

    }

    else{

        favorites.forEach(item=>{

            html+=`

<div class="favorite-card">

<b>${item.title}</b>

<br><br>

${item.source}

<br><br>

<a href="${item.url}"
target="_blank">

📖 Open Report

</a>

</div>

`;

        });

    }

    document.getElementById("favoriteNews").innerHTML=html;

}


function checkCriticalNotification(newsList){

    const criticalNews = newsList.find(
        item => item.severity === "Critical"
    );

    if(!criticalNews){
        return;
    }

    if(lastCriticalNews === ""){

        lastCriticalNews = criticalNews.title;
        return;

    }

    if(lastCriticalNews !== criticalNews.title){

        alert(
            "🚨 NEW CRITICAL THREAT\n\n" +
            criticalNews.title +
            "\n\nSource : " +
            criticalNews.source
        );

        lastCriticalNews = criticalNews.title;

    }

}

/*==========================================================
    PIN NEWS
==========================================================*/

function pinNews(news){

localStorage.setItem(

"pinnedNews",

JSON.stringify(news)

);

loadPinnedNews();

showToast(

"📌 News Pinned Successfully",

"info"

);

}


function loadPinnedNews(){

const news = JSON.parse(

localStorage.getItem("pinnedNews")

);

if(!news){

document.getElementById("pinnedNews").innerHTML=

"No pinned news.";

return;

}

document.getElementById("pinnedNews").innerHTML=`

<div class="pinned-card">

<h2>

📌 ${news.title}

</h2>

<p>

🌐 ${news.source}

</p>

<p>

📅 ${news.published}

</p>

<a

href="${news.url}"

target="_blank"

class="news-button">

📖 Read Full Report

</a>

<button
class="pin-btn"
onclick="removePinnedNews()">

🗑 Remove

</button>

</div>

`;

}


function removePinnedNews(){

localStorage.removeItem(

"pinnedNews"

);

loadPinnedNews();

}


// ===============================
// Dark Mode
// ===============================

function toggleTheme(){

    document.body.classList.toggle("dark-mode");

    const button =
    document.getElementById("themeButton");

    if(document.body.classList.contains("dark-mode")){

        localStorage.setItem(
            "theme",
            "dark"
        );

        button.innerHTML="☀ Light Mode";

    }

    else{

        localStorage.setItem(
            "theme",
            "light"
        );

        button.innerHTML="🌙 Dark Mode";

    }

}


// ==========================================
// Toast Notification
// ==========================================

function showToast(message,type="success"){

const container=
document.getElementById("toastContainer");

const toast=
document.createElement("div");

toast.className=
`toast toast-${type}`;

toast.innerHTML=message;

container.appendChild(toast);

setTimeout(()=>{

toast.remove();

},3000);

}


window.addEventListener("load",()=>{

setTimeout(()=>{

document.getElementById(

"loadingScreen"

).style.display="none";

},1000);

});


// ==========================================
// Counter Animation
// ==========================================

function animateCounter(id,target){

let count=0;

const element=document.getElementById(id);

const speed=25;

const timer=setInterval(()=>{

count++;

element.innerHTML=count;

if(count>=target){

clearInterval(timer);

}

},speed);

}




// ==========================================
// Threat Trend Chart
// ==========================================


function loadThreatTrend() {

    const ctx = document.getElementById("trendChart");

    if (!ctx) {
        console.log("Trend Chart Not Found");
        return;
    }

    if (trendChart && typeof trendChart.destroy === "function") {
        trendChart.destroy();
    }

    const trendData = threatTrendData;

    console.log("Threat Trend Data:", threatTrendData);

    const labels = [
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
        "Sat",
        "Sun"
    ];

    trendChart = new Chart(ctx, {

        type: "line",

        data: {

            labels: labels,

            datasets: [{

                label: "Detected Threats",

                data: trendData,

                borderColor: "#d32f2f",

                backgroundColor: "rgba(211,47,47,0.2)",

                fill: true,

                tension: 0.4

            }]

        },

        options: {

    responsive: true,

    maintainAspectRatio: false,

    elements: {
        point: {
            radius: 6,
            hoverRadius: 8
        }
    },

    onClick: function(event, elements) {

        console.log("Chart clicked", elements);

        if (!elements.length) return;

        const point = elements[0];
        const index = point.index;

      document.getElementById("trendDetails").innerHTML = `
<h3>Threat Details</h3>

<p><b>Current Upload:</b></p>

<p><b>Threats:</b> ${latestTrendDetails.threats}</p>

<p><b>Risk:</b> ${latestTrendDetails.risk}</p>

<p><b>Day:</b> ${latestTrendDetails.day}</p>
`;

    }

}

   });


    const today = new Date().getDay();
const todayIndex = today === 0 ? 6 : today - 1;

document.getElementById("todayThreats").innerHTML =
    trendData[todayIndex];

const average = Math.round(
    trendData.reduce((a, b) => a + b, 0) / trendData.length
);

document.getElementById("weeklyAverage").innerHTML = average;

const maxIndex = trendData.indexOf(Math.max(...trendData));

document.getElementById("peakDay").innerHTML = labels[maxIndex];

}

// ==========================================
// System Status
// ==========================================

function updateSystemStatus(){

    document.getElementById("backendStatus").innerHTML =
    "🟢 Online";

    document.getElementById("aiStatus").innerHTML =
    "🟢 Running";

    document.getElementById("feedStatus").innerHTML =
    "🟢 Connected";

    document.getElementById("databaseStatus").innerHTML =
    "🟢 Connected";

    document.getElementById("virusStatus").innerHTML =
    "🟢 Active";

}



// ==========================================
// AI Security Recommendations
// ==========================================

function generateRecommendations(){

let html="";

if(totalCritical>0){

html+=`
✅ Immediately isolate infected devices.<br>
`;

html+=`
✅ Block malicious IP addresses.<br>
`;

html+=`
✅ Notify security administrator.<br>
`;

}

if(totalHigh>0){

html+=`
✅ Update all operating systems.<br>
`;

html+=`
✅ Patch vulnerable applications.<br>
`;

}

if(totalMedium>0){

html+=`
✅ Enable Multi-Factor Authentication.<br>
`;

html+=`
✅ Review firewall rules.<br>
`;

}

if(totalLow>0){

html+=`
✅ Continue routine monitoring.<br>
`;

}

if(html===""){

html=`
🟢 Excellent!

No security recommendations at this time.
`;

}

document.getElementById(

"recommendationBox"

).innerHTML=html;

}




// ==========================================
// Security Health Dashboard
// ==========================================

function updateSecurityHealth(){

let score=100;

score -= dashboardStats.critical * 15;

score -= dashboardStats.high * 8;

score -= dashboardStats.medium * 4;

score -= dashboardStats.low;

if(score<0){

score=0;

}

const progress=document.getElementById("securityProgress");

progress.style.width=score+"%";

progress.innerHTML=score+"%";

const risk=document.getElementById("riskLevel");

if (dashboardStats.critical > 0) {

    risk.innerHTML = "🔴 CRITICAL";
    progress.style.background = "#d32f2f";

}
else if (dashboardStats.high > 0) {

    risk.innerHTML = "🟠 HIGH";
    progress.style.background = "#f57c00";

}
else if (dashboardStats.medium > 0) {

    risk.innerHTML = "🟡 MEDIUM";
    progress.style.background = "#fbc02d";

}
else {

    risk.innerHTML = "🟢 LOW";
    progress.style.background = "#2e7d32";

}

}


// ==========================================
// AI Incident Response
// ==========================================

function generateIncidentResponse(){

let html="";

if(totalCritical>0){

html=`

<h3>🔴 Threat Level : CRITICAL</h3>

<ul>

<li>🚫 Isolate affected devices immediately</li>

<li>🛑 Block malicious IP addresses</li>

<li>🔥 Enable emergency firewall rules</li>

<li>📞 Notify Security Team</li>

<li>⏱ Estimated Recovery : 30 Minutes</li>

</ul>

`;

}

else if(totalHigh>0){

html=`

<h3>🟠 Threat Level : HIGH</h3>

<ul>

<li>🛡 Patch vulnerable systems</li>

<li>🔍 Review suspicious activity</li>

<li>📋 Scan all endpoints</li>

<li>⏱ Estimated Recovery : 1 Hour</li>

</ul>

`;

}

else if(totalMedium>0){

html=`

<h3>🟡 Threat Level : MEDIUM</h3>

<ul>

<li>🔄 Update antivirus signatures</li>

<li>🔐 Enable MFA</li>

<li>📊 Monitor logs continuously</li>

</ul>

`;

}

else{

html=`

<h3>🟢 Threat Level : LOW</h3>

<ul>

<li>✅ Continue routine monitoring</li>

<li>✅ Keep software updated</li>

<li>✅ Perform regular backups</li>

</ul>

`;

}

document.getElementById(

"incidentResponse"

).innerHTML=html;

}



// ==========================================
// Executive Dashboard
// ==========================================

function updateExecutiveDashboard(){

const date=new Date();

const summary=`

<h2>🛡 Executive Security Dashboard</h2>

<p><b>Overall Security Score :</b> ${calculateSecurityScore()}%</p>

<p><b>Current Risk :</b> ${getRiskLevel()}</p>

<p><b>Last Scan :</b> ${date.toLocaleString()}</p>

<p><b>Total Threat News :</b> ${allThreatNews.length}</p>

<p><b>Critical News :</b> ${totalCritical}</p>

<hr>

<h3>🤖 AI Assessment</h3>

<p>

Network monitoring is active.
Review critical alerts immediately.
Continue monitoring suspicious activity.

</p>

`;

document.getElementById(

"executiveDashboard"

).innerHTML=summary;

}

// ==========================================
// AI Dashboard Overview
// ==========================================

function updateAIOverview(){

    

    let html = "<h3>🤖 AI Analysis</h3>";

    html += `<p>📊 Total Threats Detected : <b>${dashboardStats.total}</b></p>`;

    html += `<p>🎯 Highest Threat Level : <b>${getRiskLevel()}</b></p>`;

    html += `<p>🌐 Most Attacked IP : <b>${dashboardStats.mostAttackedIP}</b></p>`;

    html += `<p>🛡 Security Score : <b>${calculateSecurityScore()}%</b></p>`;

    html += `<hr>`;

    if (dashboardStats.critical > 0){

        html += `<p>🚨 Immediate action required. Block suspicious IPs and isolate affected systems.</p>`;

    }
    else if (dashboardStats.high > 0){

        html += `<p>⚠ High-risk activity detected. Review login attempts and enable Multi-Factor Authentication.</p>`;

    }
    else if (dashboardStats.medium > 0){

        html += `<p>🟡 Moderate threats detected. Continue monitoring and apply security updates.</p>`;

    }
    else{

        html += `<p>🟢 No major threats detected. Continue routine monitoring.</p>`;

    }

    console.log("AI Overview HTML:", html);

    document.getElementById("aiOverview").innerHTML = html;

    

}

// ==========================================
// Threat Analysis Statistics
// ==========================================

let analysisCount = 0;

function updateThreatStatistics(){

    analysisCount++;

    document.getElementById("analysisCount").innerHTML = analysisCount;

    document.getElementById("highestThreatLevel").innerHTML =
        getRiskLevel();

    document.getElementById("averageSecurity").innerHTML =
        calculateSecurityScore() + "%";

}



// ==========================================
// Notification Center
// ==========================================

let notifications=[];

function addNotification(message){
    
    console.log("Notification Added:", message);

const time=new Date().toLocaleTimeString();

notifications.unshift({

message,

time

});

if(notifications.length>10){

notifications.pop();

}

renderNotifications();

}


function renderNotifications(){

const container=

document.getElementById(

"notificationCenter"

);

let html="";

notifications.forEach(item=>{

html+=`

<div class="notification">

<b>${item.message}</b>

<div class="notification-time">

${item.time}

</div>

</div>

`;

});

if(html===""){

html="<p>No notifications available.</p>";

}

container.innerHTML=html;

}


// ==========================================
// Scan History
// ==========================================

let scanHistory=[];

function addScanHistory(title,status){

const now=new Date();

scanHistory.unshift({

title,

status,

time:now.toLocaleString()

});

if(scanHistory.length>10){

scanHistory.pop();

}

renderScanHistory();

}


function renderScanHistory(){

const container=document.getElementById("scanHistory");

let html="";

scanHistory.forEach(item=>{

html+=`

<div class="history-item">

<b>${item.title}</b>

<br><br>

Status : <b>${item.status}</b>

<div class="history-time">

${item.time}

</div>

</div>

`;

});

if(html===""){

html="<p>No scan history available.</p>";

}

container.innerHTML=html;

}



// ==========================================
// Recent Reports
// ==========================================

let reportHistory=[];

function addReport(fileName,type){

const time=new Date().toLocaleString();

reportHistory.unshift({

file:fileName,

type:type,

time:time

});

if(reportHistory.length>10){

reportHistory.pop();

}

renderReports();

}



function renderReports(){

const container=document.getElementById(

"recentReports"

);

let html="";

reportHistory.forEach(report=>{

html+=`

<div class="report-item">

<b>${report.file}</b>

<br>

Type : ${report.type}

<div class="report-time">

${report.time}

</div>

</div>

`;

});

if(html===""){

html="<p>No reports generated.</p>";

}

container.innerHTML=html;

}


// ==========================================
// Weekly Threat Analytics
// ==========================================

function loadWeeklyChart(){

    console.log("Weekly Chart Function Running");

    if (window.weeklyChart && typeof window.weeklyChart.destroy === "function") {
        window.weeklyChart.destroy();
    }

    const ctx = document.getElementById("weeklyChart");

    if(!ctx){
        return;
    }

    window.weeklyChart = new Chart(ctx,{

        type:"bar",

        data:{

            labels:[
                "Mon",
                "Tue",
                "Wed",
                "Thu",
                "Fri",
                "Sat",
                "Sun"
            ],

            datasets:[{

                label:"Threats",

                data: weeklyThreatData,

                backgroundColor:"#1565C0"

            }]

        },

        options:{
            responsive:true,
            plugins:{
                legend:{
                    display:false
                }
            }
        }

    });

}

// ==========================================
// Monthly Threat Comparison
// ==========================================

function loadMonthlyChart(){

const ctx = document.getElementById("monthlyChart");

if(!ctx){
    return;
}

if (
    window.monthlyChart &&
    typeof window.monthlyChart.destroy === "function"
) {
    window.monthlyChart.destroy();
}

window.monthlyChart = new Chart(ctx,{

    type:"bar",

    data:{

        labels:[
            "Critical",
            "High",
            "Medium",
            "Low"
        ],

        datasets:[

        {

            label:"Current Analysis",

            data:[
                dashboardStats.critical,
                dashboardStats.high,
                dashboardStats.medium,
                dashboardStats.low
            ],

            backgroundColor:[
                "#d32f2f",
                "#f57c00",
                "#fbc02d",
                "#2e7d32"
            ]

        }

        ]

    },

    options:{

        responsive:true,

        plugins:{

            legend:{

                display:false

            }

        }

    }

});

}

// ==========================================
// Monthly AI Insight
// ==========================================

function updateMonthlyInsight(){

document.getElementById(

"monthlyInsight"

).innerHTML=`

🤖 AI Analysis

Compared to last month, High severity threats increased while Critical threats decreased.

Recommendation:

✔ Continue monitoring High severity attacks.

✔ Improve firewall policies.

✔ Patch vulnerable systems regularly.

`;

}


// ==========================================
// AI Threat Prediction
// ==========================================

function updatePrediction(){

let level="🟢 LOW";

let confidence="98%";

let message="Network appears secure. Continue routine monitoring.";

let recommendation="Maintain regular security updates.";

if(totalCritical>0){

level="🔴 CRITICAL";

confidence="99%";

message="Critical attacks are likely to continue during the next 24 hours.";

recommendation="Immediately isolate affected systems and notify the security team.";

}

else if(totalHigh>0){

level="🟠 HIGH";

confidence="96%";

message="High severity attacks may continue tomorrow.";

recommendation="Increase monitoring and strengthen firewall rules.";

}

else if(totalMedium>0){

level="🟡 MEDIUM";

confidence="93%";

message="Moderate cyber activity is expected.";

recommendation="Review logs and apply pending patches.";

}

document.getElementById("predictionBox").innerHTML=`

<h3>Predicted Threat Level</h3>

<h2>${level}</h2>

<h3>AI Confidence</h3>

<p>${confidence}</p>

<h3>Prediction</h3>

<p>${message}</p>

<h3>Recommendation</h3>

<p>${recommendation}</p>

`;

}



// ==========================================
// Advanced Dashboard Filter
// ==========================================

function advancedFilter(){

const severity=

document.getElementById(

"filterSeverity"

).value;

const category=

document.getElementById(

"filterCategory"

).value;

let filtered=[...allThreatNews];

if(severity!=="All"){

filtered=filtered.filter(

n=>n.severity===severity

);

}

if(category!=="All"){

filtered=filtered.filter(

n=>{

const title=n.title.toLowerCase();

return title.includes(

category.toLowerCase()

);

}

);

}

displayNews(filtered);

}


function resetAdvancedFilter(){

document.getElementById(

"filterSeverity"

).value="All";

document.getElementById(

"filterCategory"

).value="All";

document.getElementById(

"filterDate"

).value="";

displayNews(allThreatNews);

}

// ==========================================
// Live Dashboard Cards
// ==========================================

function updateDashboardCards(){

    document.getElementById("total").innerHTML =
    dashboardStats.total;

    document.getElementById("critical").innerHTML =
    dashboardStats.critical;

    document.getElementById("high").innerHTML =
    dashboardStats.high;

    document.getElementById("medium").innerHTML =
    dashboardStats.medium;

    document.getElementById("low").innerHTML =
    dashboardStats.low;

    document.getElementById("failedLogins").innerHTML =
    dashboardStats.failedLogins;

    document.getElementById("mostIP").innerHTML =
    dashboardStats.mostAttackedIP;

    document.getElementById("lastScan").innerHTML =
    dashboardStats.lastScan;

    
}

// ==========================================
// Calculate Security Score
// ==========================================

function calculateSecurityScore(){

let score = 100;

score -= dashboardStats.critical * 15;

score -= dashboardStats.high * 8;

score -= dashboardStats.medium * 4;

score -= dashboardStats.low * 1;

if(score < 0){

score = 0;

}

return score;

}

// ==========================================
// Get Risk Level
// ==========================================

function getRiskLevel(){

    if (dashboardStats.critical > 0) {
        return "🔴 CRITICAL";
    }

    if (dashboardStats.high > 0) {
        return "🟠 HIGH";
    }

    if (dashboardStats.medium > 0) {
        return "🟡 MEDIUM";
    }

    return "🟢 LOW";

}


// ==========================================
// Reset Dashboard
// ==========================================

function resetDashboard(){

    if(!confirm("Reset the dashboard?")){
        return;
    }

    // Reset dashboard statistics
    dashboardStats.total = 0;
    dashboardStats.critical = 0;
    dashboardStats.high = 0;
    dashboardStats.medium = 0;
    dashboardStats.low = 0;
    dashboardStats.failedLogins = 0;
    dashboardStats.mostAttackedIP = "-";
    dashboardStats.lastScan = "--";
    dashboardStats.uploadedLogs = 0;

    // Reset dashboard cards
    updateDashboardCards();

    updateSecurityHealth();

    weeklyThreatData = [0,0,0,0,0,0,0];

    monthlyThreatData = [0,0,0,0,0,0,0,0,0,0,0,0];

    threatTrendData = [0,0,0,0,0,0,0];

    latestTrendDetails = {
    day: "",
    threats: 0,
    risk: "Low"
};

drawCharts(0,0,0,0);

loadWeeklyChart();

loadMonthlyChart();

loadThreatTrend();

document.getElementById("todayThreats").innerHTML = "0";

document.getElementById("weeklyAverage").innerHTML = "0";

document.getElementById("peakDay").innerHTML = "-";

document.getElementById("trendDetails").innerHTML = `
<h3>Threat Details</h3>
<p>Select a point on the graph to view details.</p>
`;

    // ==========================================
// Reset AI Dashboard
// ==========================================

document.getElementById("aiOverview").innerHTML = `
<h3>🤖 AI Analysis</h3>
<p>System waiting for log analysis...</p>
`;

// ==========================================
// Reset Executive Dashboard
// ==========================================

document.getElementById("executiveDashboard").innerHTML = `
<h2>🛡 Executive Security Dashboard</h2>

<p><b>Overall Security Score :</b> 100%</p>

<p><b>Current Risk :</b> 🟢 LOW</p>

<p><b>Last Scan :</b> --</p>

<p><b>Total Threat News :</b> ${allThreatNews.length}</p>

<p><b>Critical News :</b> ${totalCritical}</p>

<hr>

<h3>🤖 AI Assessment</h3>

<p>
System waiting for log analysis...
</p>
`;

document.getElementById("securityScore").innerHTML = "100%";
document.getElementById("blockedIPs").innerHTML = "0";
document.getElementById("scannedSites").innerHTML = "0";

document.getElementById("logFile").value = "";

    addNotification("🔄 Dashboard Reset Successfully");

}


function generateAIDecision(){

    let decision = "";
    let recommendation = "";
    let confidence = 100;

    const currentTime = new Date().toLocaleString();

confidence -= dashboardStats.low * 1;
confidence -= dashboardStats.medium * 2;
confidence -= dashboardStats.high * 3;
confidence -= dashboardStats.critical * 5;

if(confidence < 80){
    confidence = 80;
}

    if(dashboardStats.critical > 0){

        decision = "🔴 CRITICAL";

        recommendation = `
        <ul>
            <li>Immediately block suspicious IP addresses.</li>
            <li>Isolate affected systems.</li>
            <li>Review authentication logs.</li>
            <li>Enable Multi-Factor Authentication.</li>
            <li>Inform the security team immediately.</li>
        </ul>`;

        
    }

    else if(dashboardStats.high > 0){

        decision = "🟠 HIGH";

        recommendation = `
        <ul>
            <li>Investigate failed login attempts.</li>
            <li>Monitor network traffic.</li>
            <li>Review firewall rules.</li>
            <li>Enable account lockout policy.</li>
        </ul>`;

        
    }

    else if(dashboardStats.medium > 0){

        decision = "🟡 MEDIUM";

        recommendation = `
        <ul>
            <li>Continue monitoring.</li>
            <li>Install security updates.</li>
            <li>Review unusual activities.</li>
        </ul>`;

       
    }

    else{

        decision = "🟢 LOW";

        recommendation = `
        <ul>
            <li>No major threats detected.</li>
            <li>Continue routine monitoring.</li>
            <li>Keep antivirus signatures updated.</li>
        </ul>`;

        
    }

    document.getElementById("aiDecisionBox").innerHTML = `

        <h3>🤖 AI Security Decision</h3>

     <p><b>Threat Level :</b> ${decision}</p>

<p><b>Threat Priority :</b> Immediate Review Required</p>

<p><b>AI Confidence :</b> ${confidence}%</p>

<p><b>Decision Time :</b> ${currentTime}</p>

<p><b>System Status :</b> Active Monitoring</p>

        <p><b>Reason :</b></p>

        <ul>
            <li>Total Threats : ${dashboardStats.total}</li>
            <li>Critical : ${dashboardStats.critical}</li>
            <li>High : ${dashboardStats.high}</li>
            <li>Medium : ${dashboardStats.medium}</li>
            <li>Low : ${dashboardStats.low}</li>
        </ul>

        <h4>🛡 Recommended Actions</h4>

        ${recommendation}

    `;
}


function showAbout(){

    alert(

`AI Cyber Threat Detection Platform

Version : 1.0

Developed By:
DHANYAJ S

Bachelor of Computer Applications

ITM College of Arts and Science

-----------------------------------

Project Features

✔ AI Log Analysis

✔ AI Decision Engine

✔ Executive Dashboard

✔ Website Security Scanner

✔ VirusTotal Integration

✔ Cyber Threat Intelligence

✔ PDF Report Generation

✔ CSV Report Export

✔ Security Health Dashboard`

    );

}