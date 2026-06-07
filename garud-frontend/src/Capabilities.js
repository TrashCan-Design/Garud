import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Activity, Zap, Search, Terminal, Lock, Globe, Layers,
  Cpu, MousePointer2, AlertTriangle, CheckCircle, Database, Code,
  RefreshCw, Server, Play, ChevronRight, Info, ExternalLink, HelpCircle,
  Eye, FileText, ArrowRight
} from 'lucide-react';
import './Capabilities.css';


const iconMap = {
  Database: Database,
  Code: Code,
  Lock: Lock,
  Globe: Globe,
  Terminal: Terminal,
  Layers: Layers,
  Shield: Shield,
  Cpu: Cpu,
  Activity: Activity,
  Search: Search,
  RefreshCw: RefreshCw,
  Server: Server,
  Zap: Zap,
  MousePointer2: MousePointer2
};


const capabilitiesData = [

  {
    id: "sqli",
    category: "native",
    iconName: "Database",
    title: "SQL Injection (SQLi)",
    description: "Detects blind, error-based, and union-based injection vulnerabilities using heuristic SQL syntax parsing and automated query testing.",
    severity: "Critical",
    cwe: "CWE-89",
    mitigation: "Enforce parameterized queries (prepared statements), use ORMs, and perform strict input validation."
  },
  {
    id: "xss",
    category: "native",
    iconName: "Code",
    title: "Cross-Site Scripting (XSS)",
    description: "Identifies Reflected, Stored, and DOM-based XSS vulnerabilities across forms, query parameters, and DOM sinks.",
    severity: "High",
    cwe: "CWE-79",
    mitigation: "Implement context-aware HTML/Javascript output encoding, utilize Content Security Policy (CSP), and sanitize user inputs."
  },
  {
    id: "bac",
    category: "native",
    iconName: "Lock",
    title: "Broken Access Control (BAC)",
    description: "Audits authorization boundaries, checks privilege escalation vectors, and tests parameter tampering on backend endpoints.",
    severity: "High",
    cwe: "CWE-284",
    mitigation: "Apply strict server-side authentication validation, default-deny access policies, and robust Role-Based Access Control (RBAC)."
  },
  {
    id: "ssrf",
    category: "native",
    iconName: "Globe",
    title: "Server-Side Request Forgery (SSRF)",
    description: "Detects input parameters that allow remote attackers to force the backend server to make unauthorized requests to internal networks.",
    severity: "Critical",
    cwe: "CWE-918",
    mitigation: "Restrict outgoing traffic, implement destination domain whitelists, and block private IP address ranges (RFC 1918)."
  },
  {
    id: "xpath",
    category: "native",
    iconName: "Terminal",
    title: "XPath Injection",
    description: "Identifies malformed XML query inputs that allow attackers to bypass authentication or extract XML database properties.",
    severity: "High",
    cwe: "CWE-91",
    mitigation: "Validate input values using whitelists and implement parameterized XML query builders."
  },
  {
    id: "path-traversal",
    category: "native",
    iconName: "Layers",
    title: "Path Traversal & LFI",
    description: "Locates file path parameters that allow attackers to escape directory roots (`../`) to access local configuration or system files.",
    severity: "High",
    cwe: "CWE-22",
    mitigation: "Avoid direct file path inputs, map file access to database IDs, and canonicalize path inputs before resolution."
  },
  {
    id: "cryptography",
    category: "native",
    iconName: "Shield",
    title: "Cryptographic Failures",
    description: "Scans server SSL/TLS handshakes, tests for deprecated ciphers, and checks for transmission in cleartext or weak hashing usage.",
    severity: "High",
    cwe: "CWE-310",
    mitigation: "Enforce TLS 1.3, configure modern secure ciphers, hash passwords with bcrypt or Argon2, and enforce HTTPS via HSTS."
  },
  {
    id: "outdated-components",
    category: "native",
    iconName: "Cpu",
    title: "Vulnerable Components Check",
    description: "Audits repository dependencies, checks library manifests against global CVE databases, and highlights end-of-life components.",
    severity: "Medium",
    cwe: "CWE-1104",
    mitigation: "Integrate automated software composition analysis (SCA), configure dependabot, and keep dependency trees updated."
  },
  {
    id: "dos",
    category: "native",
    iconName: "Activity",
    title: "DoS & Rate Limit Auditor",
    description: "Assesses API resilience against application-layer flood attacks and verifies the presence of rate-limiting middleware.",
    severity: "Medium",
    cwe: "CWE-400",
    mitigation: "Configure Web Application Firewalls (WAF), enforce strict API rate limiting, and apply request payload size limits."
  },
  {
    id: "exposed-panels",
    category: "native",
    iconName: "Search",
    title: "Security Misconfigurations",
    description: "Scans site directories for exposed administrative panels, configuration backups, debug logs, or active Git/Subversion directories.",
    severity: "Medium",
    cwe: "CWE-200",
    mitigation: "Deactivate debug output in production, configure web server directory listings to 'off', and block admin portals by IP."
  },
  {
    id: "integrity",
    category: "native",
    iconName: "RefreshCw",
    title: "Software & Data Integrity",
    description: "Verifies hashes, analyzes data delivery pipelines, and checks packages for susceptibility to supply chain tampering.",
    severity: "High",
    cwe: "CWE-353",
    mitigation: "Implement digital signatures for software updates, verify checksums (SHA-256), and secure build pipelines."
  },
  {
    id: "api-scanner",
    category: "native",
    iconName: "Server",
    title: "API Endpoint Auditor",
    description: "Performs targeted security scans of REST/JSON endpoints, validating headers, auth schemas, and request schemas.",
    severity: "High",
    cwe: "CWE-284",
    mitigation: "Enforce strict JSON schema validation, authorize all REST calls on backend, and restrict CORS origins."
  },


  {
    id: "nuclei",
    category: "containerized",
    iconName: "Zap",
    title: "Nuclei Template Probe",
    description: "Launches vulnerability scans using thousands of community-maintained YAML templates to pinpoint CVEs and server misconfigurations.",
    severity: "Critical",
    cwe: "Multi-CWE",
    mitigation: "Apply security patches matching flagged CVEs immediately and update Nuclei template rules regularly."
  },
  {
    id: "sqlmap",
    category: "containerized",
    iconName: "Database",
    title: "SQLMap Deep Exploitation",
    description: "Automates verification and exploit validation of detected SQL injections, auditing backend databases and schemas.",
    severity: "Critical",
    cwe: "CWE-89",
    mitigation: "Ensure SQL injection vulnerabilities are fixed in application code, removing parameters SQLMap can exploit."
  },
  {
    id: "nikto",
    category: "containerized",
    iconName: "Globe",
    title: "Nikto Web Server Scanner",
    description: "Audits HTTP daemons, checks for 6700+ potentially dangerous files/programs, and flags outdated server software.",
    severity: "Medium",
    cwe: "CWE-200",
    mitigation: "Keep web server engines (Nginx, Apache) patched, hide server banner headers, and delete default web files."
  },
  {
    id: "tsunami",
    category: "containerized",
    iconName: "Shield",
    title: "Google Tsunami Scanner",
    description: "Executes enterprise-grade network port and protocol checks to verify high-impact vulnerabilities with minimal false positives.",
    severity: "Critical",
    cwe: "Multi-CWE",
    mitigation: "Patch vulnerable software running on exposed ports and apply firewall filtering rules."
  },
  {
    id: "nmap",
    category: "containerized",
    iconName: "Search",
    title: "Nmap Network Mapping",
    description: "Runs low-level network port scanning to discover active sockets, verify open ports, and fingerprint target operating systems.",
    severity: "Info",
    cwe: "CWE-200",
    mitigation: "Close unused ports, restrict system access via firewalls, and place internal database systems behind VPNs."
  },


  {
    id: "playwright",
    category: "crawlers",
    iconName: "MousePointer2",
    title: "Playwright Headless Crawler",
    description: "Crawls modern Single Page Applications (SPAs) by launching headless Chromium, rendering JavaScript, and capturing dynamic routes.",
    severity: "Info",
    cwe: "Recon",
    mitigation: "Allows Garud to scan client-side dynamic content, routers, and dynamic click-paths."
  },
  {
    id: "scrapy",
    category: "crawlers",
    iconName: "Cpu",
    title: "Scrapy Concurrent Crawler",
    description: "Executes asynchronous crawling at high speeds, mapping target file structures and input fields on wide networks.",
    severity: "Info",
    cwe: "Recon",
    mitigation: "Enables comprehensive url discovery, cataloging input parameters for downstream scanners."
  },
  {
    id: "beautifulsoup",
    category: "crawlers",
    iconName: "Layers",
    title: "BeautifulSoup Crawler",
    description: "Parses static HTML pages to extract forms, inputs, and links with minimal resource footprint.",
    severity: "Info",
    cwe: "Recon",
    mitigation: "Maps simple static web pages rapidly during the initial stage of reconnaissance."
  }
];


const terminalLogs = [
  { text: "$ garud scan --target staging.api.internal", delay: 100 },
  { text: "[+] Initializing Garud Vulnerability Scanning Engine (v3.5)...", delay: 400 },
  { text: "[+] Host resolved: staging.api.internal -> 192.168.10.45", delay: 200 },
  { text: "[+] Performing TCP port sweep (Nmap)...", delay: 600 },
  { text: "    └── Port 80 (HTTP) -> OPEN (nginx 1.18.0)", delay: 100 },
  { text: "    └── Port 443 (HTTPS) -> OPEN (nginx 1.18.0)", delay: 100 },
  { text: "    └── Port 8080 (Admin Portal) -> OPEN (Apache Tomcat)", delay: 150 },
  { text: "[+] Starting target discovery crawlers (BeautifulSoup + Scrapy)...", delay: 500 },
  { text: "    └── Discovered 28 static paths, 6 form controllers", delay: 200 },
  { text: "[+] Initializing Playwright Headless SPA crawler...", delay: 700 },
  { text: "    └── Rendered Javascript application tree", delay: 300 },
  { text: "    └── Discovered 14 client-side route paths, 3 private API endpoints", delay: 200 },
  { text: "[+] Executing native diagnostic scanners...", delay: 600 },
  { text: "    └── SQLi Scanner: COMPLETE (No injection points found)", delay: 200 },
  { text: "    └── XSS Scanner: WARNING - Reflected XSS verified on '/search?q='", delay: 250, type: "warning" },
  { text: "        └── Payload: <script>alert(document.domain)</script>", delay: 50 },
  { text: "    └── SSRF Scanner: COMPLETE (Endpoint inputs securely filtered)", delay: 200 },
  { text: "    └── Cryptographic Failures: WARNING - SSL/TLS deprecated protocols supported", delay: 300, type: "warning" },
  { text: "        └── Insecure Protocol detected: TLS 1.0, TLS 1.1 enabled", delay: 50 },
  { text: "    └── Exposed Admin Panels: ALERT - exposed configuration panel on port 8080", delay: 400, type: "danger" },
  { text: "[+] Running containerized security scanners (Garud Sec-Tools)...", delay: 700 },
  { text: "    └── Nuclei Probe: running...", delay: 400 },
  { text: "        └── [nuclei] [cve-2021-41773] [medium] - Nginx directory traversal patch mismatch", delay: 200, type: "warning" },
  { text: "    └── SQLMap Engine: running... smart testing forms -> Clean", delay: 500 },
  { text: "    └── Nikto Scanner: running... header validation", delay: 300 },
  { text: "        └── [nikto] Missing X-Frame-Options header (Clickjacking vulnerability)", delay: 150, type: "warning" },
  { text: "        └── [nikto] Missing Content-Security-Policy header", delay: 100, type: "warning" },
  { text: "[+] Scanning cycle finished. Synthesizing security reports...", delay: 500 },
  { text: "[+] Running threat scoring algorithm (CWE-to-CVSS mapping)...", delay: 400 },
  { text: "    └── Aggregated penalty weights applied: CWE-79, CWE-200, CWE-310, CWE-693", delay: 100 },
  { text: "    └── Final Security Score: 68/100 (Grade: C+)", delay: 150, type: "info" },
  { text: "    └── Severity Status: Medium Risk", delay: 100, type: "warning" },
  { text: "[+] PDF report compiled: /reports/staging_api_internal_report.pdf", delay: 200 },
  { text: "[+] Execution complete. Garud standing by.", delay: 200 }
];

const Capabilities = ({ onInitScan, goHome }) => {
  const [activeTab, setActiveTab] = useState('native');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [hoveredCard, setHoveredCard] = useState(null);


  const [terminalLines, setTerminalLines] = useState([]);
  const [isSimulating, setIsSimulating] = useState(false);
  const terminalBodyRef = useRef(null);
  const simTimeoutRef = useRef([]);

  const handleCTA = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (onInitScan) onInitScan();
    else if (goHome) goHome();
  };


  const runSimulation = () => {
    if (isSimulating) return;
    setIsSimulating(true);
    setTerminalLines([]);


    simTimeoutRef.current.forEach(clearTimeout);
    simTimeoutRef.current = [];

    let currentLines = [];
    let accumDelay = 0;

    terminalLogs.forEach((log) => {
      accumDelay += log.delay;
      const timeoutId = setTimeout(() => {
        currentLines = [...currentLines, log];
        setTerminalLines(currentLines);

        if (terminalBodyRef.current) {
          terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
        }
      }, accumDelay);
      simTimeoutRef.current.push(timeoutId);
    });

    const endTimeoutId = setTimeout(() => {
      setIsSimulating(false);
    }, accumDelay + 500);
    simTimeoutRef.current.push(endTimeoutId);
  };


  useEffect(() => {
    runSimulation();
    return () => {
      simTimeoutRef.current.forEach(clearTimeout);
    };
  }, []);


  const filteredCapabilities = capabilitiesData.filter(cap => {
    const matchesTab = cap.category === activeTab;
    const matchesSearch = cap.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cap.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cap.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || cap.severity.toLowerCase() === severityFilter.toLowerCase();

    return matchesTab && matchesSearch && matchesSeverity;
  });

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.08, delayChildren: 0.1 }
    }
  };

  const cardVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: { y: 0, opacity: 1, transition: { type: "spring", stiffness: 100, damping: 15 } }
  };

  const steps = [
    {
      number: "01",
      icon: <Globe size={20} />,
      title: "Discovery & Recon",
      desc: "Static BeautifulSoup structures, concurrent Scrapy spiders, and dynamic Playwright browser engines map the target network and client routes."
    },
    {
      number: "02",
      icon: <Search size={20} />,
      title: "Passive Headers Check",
      desc: "Checks server response attributes, audits cookies attributes (Secure, HttpOnly), and confirms security headers (CSP, HSTS, CORS)."
    },
    {
      number: "03",
      icon: <Cpu size={20} />,
      title: "Native Scanner Audits",
      desc: "Flask-driven scanners test deep parameters for web vulnerabilities, including SQLi, XSS, SSRF, XPath, and path traversals."
    },
    {
      number: "04",
      icon: <Terminal size={20} />,
      title: "Advanced Probe Injection",
      desc: "Triggers containerized scanning tools (Nuclei, SQLMap, Nikto, Google Tsunami) to analyze specific CVE templates and network services."
    },
    {
      number: "05",
      icon: <Shield size={20} />,
      title: "Unified Scoring Index",
      desc: "Aggregates scanner reports, maps CWE targets to CVSS scoring vectors, and applies severity penalties to compile a download-ready PDF."
    }
  ];

  return (
    <div className="capabilities-container max-w-7xl mx-auto px-6 py-12 text-[#F9FAFB]">


      <div className="text-center max-w-3xl mx-auto mb-16 relative">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-cyan-500/10 blur-[80px] rounded-full -z-10 animate-pulse"></div>
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-xs font-mono text-cyan-400 tracking-wider uppercase mb-6"
        >
          <Shield size={12} className="animate-pulse text-cyan-400" /> Garud Scanning Platform Capabilities
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-4xl md:text-6xl font-extrabold tracking-tight mb-6 leading-tight"
        >
          Security <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-indigo-400 to-pink-500">Architecture</span> & Engine
        </motion.h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="text-lg text-[#98A2B3] leading-relaxed"
        >
          Garud integrates an multi-threaded discovery pipeline, native heuristic security scanners, and containerized elite scanning suites to map and secure your target's perimeter.
        </motion.p>
      </div>


      <section className="mb-20">
        <div className="flex justify-between items-center mb-4">
          <div className="flex items-center gap-2">
            <Terminal size={18} className="text-cyan-400" />
            <h3 className="text-sm font-semibold tracking-wider uppercase text-[#98A2B3]">Garud Engine CLI Output</h3>
          </div>
          <button
            onClick={runSimulation}
            disabled={isSimulating}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:border-cyan-500/30 text-xs font-semibold text-cyan-400 hover:bg-cyan-500/5 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play size={12} className={isSimulating ? "animate-spin" : ""} /> {isSimulating ? "Scanning..." : "Simulate Engine Run"}
          </button>
        </div>

        <div className="terminal-window rounded-2xl border border-[#1F242F] bg-[#020408] overflow-hidden shadow-2xl">
          <div className="terminal-header bg-[#0F1218]/90 border-b border-[#1F242F] px-4 py-3.5 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
              <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
            </div>
            <div className="text-xs font-mono text-[#98A2B3] select-none">garud-engine-daemon</div>
            <div className="w-12"></div>
          </div>
          <div ref={terminalBodyRef} className="terminal-body p-6 font-mono text-xs md:text-sm text-cyan-400/90 leading-relaxed overflow-y-auto max-h-[360px] bg-[#020408]/95 scrollbar-thin">
            {terminalLines.map((line, idx) => {
              let colorClass = "text-[#F9FAFB]";
              if (line.type === "warning") colorClass = "text-yellow-400";
              else if (line.type === "danger") colorClass = "text-red-400";
              else if (line.type === "info") colorClass = "text-cyan-400";
              else if (line.text.startsWith("$")) colorClass = "text-gray-400";

              return (
                <div key={idx} className={`mb-2 font-mono ${colorClass}`}>
                  {line.text}
                </div>
              );
            })}
            {isSimulating && (
              <span className="inline-block w-2 h-4 bg-cyan-400 animate-pulse ml-1"></span>
            )}
          </div>
        </div>
      </section>


      <section className="mb-20">
        <div className="text-center mb-10">
          <h2 className="text-2xl md:text-3xl font-bold mb-4">Core Vulnerability Scanner Directory</h2>
          <p className="text-sm text-[#98A2B3] max-w-xl mx-auto">Explore the tools, scopes, and vulnerabilities analyzed by Garud's backend and security containers.</p>
        </div>


        <div className="bg-[#0F1218]/50 border border-[#1F242F] p-4 rounded-2xl mb-8 flex flex-col md:flex-row gap-4 items-center justify-between backdrop-blur-md">

          <div className="flex gap-1.5 bg-[#020408] p-1 rounded-xl border border-[#1F242F] w-full md:w-auto">
            {[
              { id: 'native', label: 'Native Scanners', count: 12 },
              { id: 'containerized', label: 'Containerized Probes', count: 5 },
              { id: 'crawlers', label: 'Crawlers & Recon', count: 3 }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setSearchQuery('');
                }}
                className={`flex-1 md:flex-initial flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-300 ${activeTab === tab.id
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-md'
                  : 'text-[#98A2B3] hover:text-[#F9FAFB] hover:bg-white/5'
                  }`}
              >
                {tab.label}
                <span className={`px-1.5 py-0.5 rounded-full text-[9px] font-bold ${activeTab === tab.id ? 'bg-cyan-500/20 text-cyan-300' : 'bg-[#1F242F] text-gray-400'
                  }`}>
                  {tab.count}
                </span>
              </button>
            ))}
          </div>


          <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto items-stretch sm:items-center">
            <div className="relative flex-1 sm:w-64">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
              <input
                type="text"
                placeholder="Search tools or CWE..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#020408] border border-[#1F242F] focus:border-cyan-500/50 outline-none text-xs md:text-sm text-[#F9FAFB] placeholder-gray-600 transition-colors"
              />
            </div>

            <div className="relative">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full sm:w-auto appearance-none pl-4 pr-10 py-2.5 rounded-xl bg-[#020408] border border-[#1F242F] focus:border-cyan-500/50 outline-none text-xs md:text-sm text-[#F9FAFB] font-semibold cursor-pointer transition-colors"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="info">Informational</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-gray-500">
                <ChevronRight size={14} className="rotate-90" />
              </div>
            </div>
          </div>
        </div>


        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          key={`${activeTab}-${severityFilter}`}
        >
          <AnimatePresence mode="popLayout">
            {filteredCapabilities.map((cap) => {
              const IconComp = iconMap[cap.iconName] || Shield;
              const isHovered = hoveredCard === cap.id;


              let severityBadgeColor = "bg-blue-500/10 text-blue-400 border-blue-500/20";
              if (cap.severity === "Critical") severityBadgeColor = "bg-red-500/10 text-red-400 border-red-500/20";
              else if (cap.severity === "High") severityBadgeColor = "bg-orange-500/10 text-orange-400 border-orange-500/20";
              else if (cap.severity === "Medium") severityBadgeColor = "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
              else if (cap.severity === "Info") severityBadgeColor = "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";

              return (
                <motion.div
                  key={cap.id}
                  variants={cardVariants}
                  layout
                  className="capability-card flex flex-col justify-between bg-[#0F1218]/65 border border-[#1F242F] hover:border-cyan-500/40 p-6 rounded-2xl transition-all duration-300 relative overflow-hidden group backdrop-blur-sm"
                  onMouseEnter={() => setHoveredCard(cap.id)}
                  onMouseLeave={() => setHoveredCard(null)}
                >
                  <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/[0.02] rounded-full blur-2xl group-hover:bg-cyan-500/[0.05] transition-all duration-300"></div>

                  <div>

                    <div className="flex justify-between items-start mb-5">
                      <div className="p-3 bg-[#020408] rounded-xl border border-[#1F242F] text-cyan-400 group-hover:text-cyan-300 group-hover:shadow-[0_0_15px_rgba(6,182,212,0.15)] transition-all duration-300">
                        <IconComp size={20} />
                      </div>
                      <div className="flex gap-2">
                        {cap.cwe !== "Recon" && cap.cwe !== "Multi-CWE" && (
                          <span className="text-[10px] font-mono text-[#98A2B3] bg-white/[0.02] border border-white/5 px-2 py-0.5 rounded-md">
                            {cap.cwe}
                          </span>
                        )}
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${severityBadgeColor}`}>
                          {cap.severity}
                        </span>
                      </div>
                    </div>


                    <h3 className="text-lg font-bold mb-3 text-[#F9FAFB] group-hover:text-white transition-colors">
                      {cap.title}
                    </h3>
                    <p className="text-xs md:text-sm text-[#98A2B3] leading-relaxed mb-4">
                      {cap.description}
                    </p>
                  </div>


                  <div className="border-t border-white/5 pt-4 mt-4">
                    {isHovered ? (
                      <motion.div
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="text-xs"
                      >
                        <div className="text-cyan-400 font-bold mb-1 flex items-center gap-1.5">
                          <CheckCircle size={12} /> Mitigation Control:
                        </div>
                        <p className="text-[#98A2B3] leading-relaxed italic">{cap.mitigation}</p>
                      </motion.div>
                    ) : (
                      <div className="flex justify-between items-center text-xs text-[#98A2B3]">
                        <span className="italic text-[10px]">Hover card to view mitigation</span>
                        <ChevronRight size={14} className="text-cyan-500 animate-pulse" />
                      </div>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>


          {filteredCapabilities.length === 0 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="col-span-full py-16 bg-[#0F1218]/20 border border-[#1F242F] rounded-2xl text-center"
            >
              <HelpCircle className="mx-auto text-gray-600 mb-4" size={40} />
              <h3 className="text-lg font-bold text-[#F9FAFB] mb-1">No Scanner Matches Found</h3>
              <p className="text-xs text-gray-500 max-w-sm mx-auto">Try refining your search terms or altering the severity filter parameters.</p>
            </motion.div>
          )}
        </motion.div>
      </section>


      <section className="mb-20">
        <div className="text-center mb-12">
          <h2 className="text-2xl md:text-3xl font-bold mb-4">Automated Scan Lifecycle</h2>
          <p className="text-sm text-[#98A2B3] max-w-md mx-auto">How Garud navigates your application to identify, verify, and document vulnerabilities.</p>
        </div>

        <div className="relative">

          <div className="hidden lg:block absolute top-[52px] left-10 right-10 h-0.5 bg-gradient-to-r from-cyan-500/20 via-indigo-500/20 to-pink-500/20 -z-10"></div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
            {steps.map((step, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 15 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: idx * 0.1, duration: 0.4 }}
                className="step bg-[#0F1218]/40 border border-[#1F242F] p-6 rounded-2xl text-left relative group hover:border-[#2E90FA]/40 transition-colors"
              >
                <div className="flex justify-between items-center mb-4">
                  <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex items-center justify-center group-hover:shadow-[0_0_15px_rgba(6,182,212,0.1)] transition-all">
                    {step.icon}
                  </div>
                  <div className="text-2xl font-mono font-black text-white/5 group-hover:text-white/10 transition-colors select-none">
                    {step.number}
                  </div>
                </div>
                <h4 className="text-[#F9FAFB] font-bold text-base mb-2 group-hover:text-cyan-400 transition-colors">
                  {step.title}
                </h4>
                <p className="text-xs md:text-sm text-[#98A2B3] leading-relaxed">
                  {step.desc}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>


      <section className="mb-20 bg-gradient-to-br from-indigo-500/[0.03] to-cyan-500/[0.03] border border-[#1F242F] p-8 md:p-12 rounded-3xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/[0.02] rounded-full blur-[100px] pointer-events-none"></div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 text-center relative z-10">
          <div className="border-b md:border-b-0 md:border-r border-white/5 pb-8 md:pb-0 md:pr-4">
            <h4 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-2">76%</h4>
            <div className="text-xs md:text-sm font-bold text-[#F9FAFB] mb-1">Confidence Score Accuracy</div>
            <p className="text-xs text-gray-500 max-w-[200px] mx-auto">Calculated from dynamic multi-crawler validation checks.</p>
          </div>
          <div className="border-b md:border-b-0 md:border-r border-white/5 pb-8 md:pb-0 md:pr-4">
            <h4 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-500 mb-2">12</h4>
            <div className="text-xs md:text-sm font-bold text-[#F9FAFB] mb-1">Native Diagnostic Modules</div>
            <p className="text-xs text-gray-500 max-w-[200px] mx-auto">Custom scripts executing direct injection checks in backend.</p>
          </div>
          <div className="border-b md:border-b-0 md:border-r border-white/5 pb-8 md:pb-0 md:pr-4">
            <h4 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-pink-500 mb-2">5</h4>
            <div className="text-xs md:text-sm font-bold text-[#F9FAFB] mb-1">Containerized Platforms</div>
            <p className="text-xs text-gray-500 max-w-[200px] mx-auto">External suites executing concurrent penetration scans on host.</p>
          </div>
          <div>
            <h4 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-pink-400 to-red-500 mb-2">&lt;15m</h4>
            <div className="text-xs md:text-sm font-bold text-[#F9FAFB] mb-1">Average Run Duration</div>
            <p className="text-xs text-gray-500 max-w-[200px] mx-auto">Parallel engine execution optimizes target scan latencies.</p>
          </div>
        </div>
      </section>


      <motion.section
        className="cta-section text-center p-8 md:p-12 rounded-3xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/10 via-[#0B0D12] to-indigo-950/10 relative overflow-hidden"
        initial={{ opacity: 0, scale: 0.95 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true }}
      >
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-cyan-500/[0.03] blur-[100px] rounded-full -z-10"></div>
        <h2 className="text-3xl md:text-4xl font-extrabold mb-4">Ready to Secure Your System?</h2>
        <p className="text-sm md:text-base text-[#98A2B3] max-w-lg mx-auto mb-8">Execute your first vulnerability assessment scan in seconds and receive automated remediation blueprints.</p>
        <button
          className="px-8 py-3 rounded-full font-bold bg-[#F9FAFB] hover:bg-[#F9FAFB]/90 text-black hover:shadow-[0_0_20px_rgba(255,255,255,0.2)] hover:translate-y-[-2px] active:translate-y-0 transition-all duration-300"
          onClick={handleCTA}
        >
          Initiate New Scan
        </button>
      </motion.section>

    </div>
  );
};

export default Capabilities;
