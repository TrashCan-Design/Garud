import React, { useState, useEffect, useRef, useMemo } from 'react';
import logo from './garud_logo.png';
import Capabilities from './Capabilities';
import { motion, AnimatePresence, useMotionValue, useSpring } from 'framer-motion';
import ForceGraph2D from 'react-force-graph-2d';
import {
  Shield, Search, Activity, AlertTriangle,
  Terminal, Globe, CheckCircle, ArrowRight,
  Layers, Wifi, ChevronDown, BookOpen, AlertCircle
} from 'lucide-react';

let CWE_REFERENCE_CACHE = {};


fetch('http://127.0.0.1:7000/api/cwe-reference')
  .then(res => res.json())
  .then(data => {
    CWE_REFERENCE_CACHE = data;
  })
  .catch(err => {
    console.warn("Could not fetch CWE reference from backend, using fallback:", err);
  });

function cleanCwe(cweStr) {
  if (!cweStr) return "";
  const match = String(cweStr).match(/(?:CWE|cwe)[-_\s]?(\d+)/i);
  return match ? `CWE-${match[1]}` : "";
}

function cleanUrlForMatching(urlStr) {
  if (!urlStr) return "";
  return urlStr.replace(/\/$/, "").toLowerCase();
}

function getCweMitreUrl(cweId) {
  const cleaned = cleanCwe(cweId);
  if (cleaned && CWE_REFERENCE_CACHE[cleaned]) {
    return CWE_REFERENCE_CACHE[cleaned].mitre || `https://cwe.mitre.org/data/definitions/${cleaned.split('-')[1]}.html`;
  }
  if (cleaned && cleaned.includes('-')) {
    const num = cleaned.split('-')[1];
    return `https://cwe.mitre.org/data/definitions/{num}.html`;
  }
  return "https://cwe.mitre.org/data/definitions/";
}

function getCvssAndSeverity(vuln) {
  let cvssVal = vuln.cvss_score !== undefined ? vuln.cvss_score : vuln.cvss;
  if (cvssVal !== undefined && cvssVal !== null && cvssVal !== "") {
    try {
      if (typeof cvssVal === 'string' && cvssVal.includes('(')) {
        cvssVal = cvssVal.split('(')[0].trim();
      }
      const cvssFloat = parseFloat(cvssVal);
      if (!isNaN(cvssFloat)) {
        let severity = "Info";
        if (cvssFloat >= 7.0) severity = "Critical";
        else if (cvssFloat >= 4.0) severity = "Medium";
        else if (cvssFloat >= 0.1) severity = "Low";
        return { cvss: cvssFloat, severity };
      }
    } catch (e) { }
  }

  const cweId = cleanCwe(vuln.cwe);
  if (cweId && CWE_REFERENCE_CACHE[cweId]) {
    const entry = CWE_REFERENCE_CACHE[cweId];
    let severity = entry.classification || "Suggestion";
    if (severity === "High") {
      severity = "Critical";
    }
    return {
      cvss: parseFloat(entry.cvss !== undefined ? entry.cvss : 0.0),
      severity
    };
  }

  return { cvss: 0.0, severity: "Suggestion" };
}

function getVulnInfo(type, cweStr) {
  const cweId = cleanCwe(cweStr);
  if (cweId && CWE_REFERENCE_CACHE[cweId]) {
    const entry = CWE_REFERENCE_CACHE[cweId];
    return {
      why: entry.why || VULN_INFO[type]?.why || DEFAULT_INFO.why,
      fix: entry.fix || VULN_INFO[type]?.fix || DEFAULT_INFO.fix
    };
  }
  if (VULN_INFO[type]) {
    return VULN_INFO[type];
  }
  return DEFAULT_INFO;
}


const LIGHT_SIZE = 600;
const LIGHT_RADIUS = LIGHT_SIZE / 2;


const SUGGESTION_TYPES = ["Missing Security Header", "CSRF Risk"];


const VULN_INFO = {
  "SQL Injection": {
    why: "Attackers can manipulate your database queries to steal, delete, or modify data.",
    fix: "Use parameterized queries (Prepared Statements) instead of string concatenation. Validate all user inputs."
  },
  "Reflected XSS": {
    why: "Attackers can inject malicious scripts that run in the victim's browser, stealing cookies or session tokens.",
    fix: "Sanitize all user input and escape data before rendering it in HTML. Implement a Content Security Policy (CSP)."
  },
  "Missing Security Header": {
    why: "Your server isn't instructing the browser on how to behave securely, leaving it open to Clickjacking or XSS.",
    fix: "Configure your web server (Nginx/Apache) to send headers like 'X-Frame-Options', 'Strict-Transport-Security', and 'Content-Security-Policy'."
  },
  "Sensitive Input Exposure": {
    why: "Sensitive fields (like passwords) might be sent over insecure HTTP or cached by the browser.",
    fix: "Ensure the site uses HTTPS. Add 'autocomplete=off' to sensitive forms. Ensure forms use POST, not GET."
  },
  "CSRF Risk": {
    why: "Attackers can trick users into performing actions (like changing a password) without their consent.",
    fix: "Implement Anti-CSRF tokens in all state-changing forms (POST/PUT/DELETE)."
  },
  "Insecure FTP": {
    why: "FTP sends credentials in cleartext. Attackers on the network can sniff passwords.",
    fix: "Disable FTP and use SFTP or SSH (Port 22) instead."
  },
  "Telnet Exposed": {
    why: "Telnet is an obsolete, insecure protocol with no encryption.",
    fix: "Close Port 23 immediately. Use SSH for remote management."
  },

  "Cryptographic Failure": {
    why: "Weak or missing encryption exposes sensitive data in transit. Attackers can intercept passwords, tokens, and personal information.",
    fix: "Enforce HTTPS with TLS 1.2+. Disable legacy protocols (TLS 1.0/1.1) and weak ciphers (RC4, DES, 3DES). Use HSTS headers."
  },
  "No HTTPS": {
    why: "All traffic is sent in plaintext. Attackers on the same network can read every request and response, including credentials.",
    fix: "Obtain a TLS certificate (e.g. Let's Encrypt) and redirect all HTTP traffic to HTTPS. Set the HSTS header."
  },
  "Information Disclosure": {
    why: "Headers like 'Server' or 'X-Powered-By' reveal your technology stack, helping attackers choose targeted exploits.",
    fix: "Remove or mask version-revealing headers in your web server configuration (e.g. 'server_tokens off' in Nginx)."
  },

  "Missing SRI": {
    why: "External scripts loaded without Subresource Integrity hashes can be tampered with if the CDN is compromised, injecting malicious code into your users' browsers.",
    fix: "Add integrity and crossorigin attributes to all external script/link tags. Generate hashes at srihash.org."
  },
  "Exposed Sensitive File": {
    why: "Files like .git/config, package.json, or CI configs are publicly accessible, potentially exposing source code, credentials, and dependency trees.",
    fix: "Block access to sensitive paths in your web server config. For Nginx: 'location ~* /\\.git { deny all; }'"
  },
  "Inline Script Exposure": {
    why: "Heavy use of inline JavaScript bypasses SRI protection and is incompatible with strict Content Security Policies.",
    fix: "Move JavaScript to external files protected by SRI. Set a CSP that disallows 'unsafe-inline'."
  },
  "External Script Without SRI (Crawl)": {
    why: "The crawler found third-party JavaScript on interior pages without integrity verification — a supply-chain attack vector.",
    fix: "Audit all dynamically loaded external scripts and add SRI hashes. Consider hosting critical libraries locally."
  },
  "VCS/Build Path in Crawler Graph": {
    why: "The crawler reached a sensitive infrastructure path (e.g. .git/, .github/, node_modules/) which should never be publicly accessible.",
    fix: "Block this path immediately at the web server or CDN layer. Audit your deployment for similar exposed paths."
  },

  "Outdated Component": {
    why: "Running outdated libraries with known CVEs gives attackers a ready-made exploit path into your application.",
    fix: "Upgrade the flagged library to the minimum safe version shown in the finding. Use automated dependency scanning (e.g. npm audit, Dependabot)."
  },

  "Database Port Open": {
    why: "Database ports (MySQL 3306, PostgreSQL 5432) are exposed to the public internet, allowing brute-force or exploit attempts.",
    fix: "Bind database services to localhost or a private network. Use firewall rules to restrict access."
  },
  "Server-Side Request Forgery": {
    why: "Attackers can trick your server into making requests to internal services, cloud metadata endpoints, or other sensitive resources.",
    fix: "Validate and sanitize all user-supplied URLs. Implement an allowlist of permitted domains and block internal IP ranges."
  },
  "Broken Access Control": {
    why: "Users can access resources or perform actions beyond their intended permissions, potentially viewing other users' data.",
    fix: "Implement server-side authorization checks on every request. Deny access by default and use role-based access control."
  },
  "Rate Limiting Missing": {
    why: "Without rate limiting, attackers can brute-force credentials, scrape data, or overwhelm your server with automated requests.",
    fix: "Implement rate limiting at the application or reverse proxy level (e.g. Nginx limit_req, express-rate-limit)."
  },
  "DoS Risk": {
    why: "The server may be vulnerable to denial-of-service attacks that can take the application offline for legitimate users.",
    fix: "Deploy a WAF or DDoS protection service (e.g. Cloudflare). Implement connection and request rate limits."
  }
};

const DEFAULT_INFO = {
  why: "This configuration poses a security risk to the application logic or user data.",
  fix: "Review the specific vulnerability description and apply standard security best practices."
};



const Navbar = ({ goHome, goCapabilities, activeView }) => (
  <motion.nav
    initial={{ y: -100 }}
    animate={{ y: 0 }}
    className="flex justify-between items-center py-6 px-6 sticky top-0 z-50"
  >
    <div onClick={goHome} className="flex items-center gap-3 cursor-pointer group">
      <div className="w-20 h-20 flex items-center justify-center">
        <img src={logo} alt="Garud Logo" className="w-16 h-16 object-contain" />
      </div>
      <span className="text-xl font-bold tracking-tight text-white transition-colors">Garud</span>
    </div>
    <div className="flex gap-4">
      <button
        onClick={goCapabilities}
        className={`px-6 py-2 rounded-full text-sm font-semibold transition ${activeView === 'capabilities' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}
      >
        Capabilities
      </button>
      <button onClick={goHome} className="bg-white hover:bg-gray-200 text-black px-5 py-2 rounded-full text-sm font-semibold transition shadow-[0_0_20px_rgba(255,255,255,0.2)]">New Scan</button>
    </div>
  </motion.nav>
);

const ComplexCard = ({ children, className, delay = 0 }) => (
  <motion.div initial={{ opacity: 0, scale: 0.95 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }} transition={{ delay, duration: 0.5 }} className={`relative rounded-3xl p-[1px] overflow-hidden group min-w-0 ${className}`}>
    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-20 group-hover:opacity-100 blur-sm transition duration-500 animate-spin-slow"></div>
    <div className="absolute inset-0 bg-[#0F1218] rounded-3xl"></div>
    <div className="relative bg-[#0F1218]/90 backdrop-blur-xl h-full rounded-3xl p-8 overflow-hidden">
      <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-[80px] pointer-events-none"></div>
      {children}
    </div>
  </motion.div>
);

const StatPill = ({ title, value, icon: Icon, color }) => (
  <div className="bg-[#0F1218] border border-white/5 rounded-3xl p-6 relative overflow-hidden group flex flex-col justify-between min-h-[180px]">
    <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition duration-500 pointer-events-none"></div>
    <div className="flex justify-between items-start mb-4 relative z-10">
      <div className={`p-3 rounded-2xl bg-opacity-10 ${color.replace('text-', 'bg-')}`}>
        <Icon size={24} className={color} />
      </div>
      <ArrowRight className="text-gray-500 group-hover:text-white transition -rotate-45" />
    </div>
    <div className="relative z-10">
      <div className="text-4xl font-bold text-white mb-1 tracking-tight">{value}</div>
      <div className="text-gray-400 text-sm font-medium">{title}</div>
    </div>
  </div>
);


const SEVERITY_ORDER = { Critical: 0, Medium: 1, Low: 2, Suggestion: 3, Info: 4 };

const getSeverityColor = (severity) => {
  if (severity === 'Suggestion') return 'bg-emerald-500 text-emerald-500';
  if (severity === 'Critical' || severity === 'High') return 'bg-red-500 text-red-500';
  if (severity === 'Medium') return 'bg-orange-500 text-orange-500';
  if (severity === 'Low') return 'bg-blue-500 text-blue-500';
  return 'bg-green-500 text-green-500'; // Info
};

const getBorderHoverColor = (severity) => {
  if (severity === 'Suggestion') return 'hover:border-emerald-500/50';
  if (severity === 'Critical' || severity === 'High') return 'hover:border-red-500/50';
  if (severity === 'Medium') return 'hover:border-orange-500/50';
  if (severity === 'Low') return 'hover:border-blue-500/50';
  return 'hover:border-green-500/50'; // Info
};

const getGlowColor = (severity) => {
  if (severity === 'Critical' || severity === 'High') return 'shadow-[0_0_15px_rgba(239,68,68,0.15)]';
  if (severity === 'Medium') return 'shadow-[0_0_15px_rgba(249,115,22,0.15)]';
  if (severity === 'Low') return 'shadow-[0_0_15px_rgba(59,130,246,0.15)]';
  if (severity === 'Suggestion') return 'shadow-[0_0_15px_rgba(16,185,129,0.15)]';
  return 'shadow-[0_0_15px_rgba(34,197,94,0.15)]'; // Info
};


const VulnInstance = ({ vuln, instanceIndex }) => {
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const info = getVulnInfo(vuln.type, vuln.cwe);
  const isSuggestion = vuln.severity === 'Suggestion';
  const severityColor = getSeverityColor(vuln.severity);

  return (
    <motion.div
      initial={{ opacity: 0, y: -5 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: instanceIndex * 0.05 }}
      className="rounded-xl bg-[#080A0F] border border-white/[0.04] hover:border-white/10 transition-all duration-200 overflow-hidden"
    >
      <div
        className="flex items-center justify-between px-4 py-3 cursor-pointer group/instance min-w-0 gap-2"
        onClick={(e) => { e.stopPropagation(); setIsDetailOpen(!isDetailOpen); }}
      >
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <div className="flex items-center justify-center w-6 h-6 rounded-md bg-white/[0.03] border border-white/5 text-gray-500 text-[10px] font-bold shrink-0">
            {instanceIndex + 1}
          </div>
          <p className="text-gray-300 text-sm truncate min-w-0 group-hover/instance:text-white transition-colors">
            {vuln.description}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {vuln.cvss_score != null && (
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-white/[0.06] border border-white/10 text-gray-300">
              <span className="text-yellow-400 font-mono">{Number(vuln.cvss_score).toFixed(1)}</span>
              {vuln.cwe && <span className="text-gray-500">|</span>}
              {vuln.cwe && <span className="text-cyan-400">{vuln.cwe}</span>}
            </div>
          )}
          <div className={`hidden sm:block px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-opacity-10 ${severityColor}`}>
            {vuln.severity}
          </div>
          <div className={`text-gray-600 group-hover/instance:text-gray-400 transition-all duration-300 ${isDetailOpen ? 'rotate-180' : ''}`}>
            <ChevronDown size={16} />
          </div>
        </div>
      </div>

      <AnimatePresence>
        {isDetailOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="border-t border-white/[0.04]"
          >
            <div className="p-4 space-y-4 bg-gradient-to-b from-white/[0.01] to-transparent" style={{ overflowWrap: 'anywhere' }}>
              <div>
                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <AlertCircle size={14} /> The Issue
                </h5>
                <p className="text-gray-300 text-sm leading-relaxed break-words">
                  {info.why}
                </p>
                <div className="flex flex-wrap items-center gap-2 mt-3">
                  {vuln.cwe ? (
                    <a
                      href={getCweMitreUrl(vuln.cwe)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                    >
                      MITRE CWE Reference: {cleanCwe(vuln.cwe)} →
                    </a>
                  ) : (
                    <span className="text-xs text-gray-400">
                      No CWE mapping &mdash; browse MITRE:{' '}
                      <a
                        href="https://cwe.mitre.org/data/definitions/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:underline"
                      >
                        https://cwe.mitre.org/data/definitions/
                      </a>
                    </span>
                  )}

                  {vuln.cwe && (
                    <a
                      href="https://cwe.mitre.org/data/definitions/699.html"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 hover:bg-emerald-500/20 transition-colors"
                    >
                      Software Development Index (CWE-699) →
                    </a>
                  )}

                  {vuln.cvss_score != null && (
                    <span className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold border ${vuln.cvss_score >= 7.0 ? 'bg-red-500/10 border-red-500/20 text-red-300'
                        : vuln.cvss_score >= 4.0 ? 'bg-orange-500/10 border-orange-500/20 text-orange-300'
                          : vuln.cvss_score >= 0.1 ? 'bg-blue-500/10 border-blue-500/20 text-blue-300'
                            : 'bg-green-500/10 border-green-500/20 text-green-300'
                      }`}>
                      CVSS {Number(vuln.cvss_score).toFixed(1)}
                    </span>
                  )}
                </div>
              </div>
              <div>
                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <Search size={14} /> Evidence
                </h5>
                <div className="bg-black/60 rounded-lg p-3 border border-white/5 font-mono text-xs text-red-300 break-all leading-relaxed overflow-x-auto max-w-full">
                  <span className="break-all">{vuln.description}</span>
                </div>
              </div>
              <div>
                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <BookOpen size={14} /> Recommendation
                </h5>
                <div className={`rounded-lg p-4 border ${isSuggestion ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-green-500/10 border-green-500/20'}`}>
                  <p className={`${isSuggestion ? 'text-emerald-100' : 'text-green-100'} text-sm leading-relaxed break-words`}>
                    {info.fix}
                  </p>
                  <p className="text-xs text-gray-400 mt-2 pt-2 border-t border-white/[0.04]">
                    <strong>Instructions:</strong> Review the remediation instructions above. Follow development-level controls for this vulnerability class using recommendations from the <a href="https://cwe.mitre.org/data/definitions/699.html" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">CWE-699 Software Development Guidelines</a>.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};


const VulnGroup = ({ type, vulns, index }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [showAllInstances, setShowAllInstances] = useState(false);


  const highestSeverity = vulns.reduce((worst, v) => {
    const wOrder = SEVERITY_ORDER[worst] ?? 99;
    const vOrder = SEVERITY_ORDER[v.severity] ?? 99;
    return vOrder < wOrder ? v.severity : worst;
  }, vulns[0].severity);

  const severityColor = getSeverityColor(highestSeverity);
  const borderHoverColor = getBorderHoverColor(highestSeverity);
  const glowColor = getGlowColor(highestSeverity);
  const count = vulns.length;
  const info = getVulnInfo(type, vulns[0]?.cwe);
  const isSuggestion = highestSeverity === 'Suggestion';

  // Show CVSS classification note when CWE and CVSS disagree
  const maxCvss = Number(Math.max(...vulns.map(v => v.cvss_score || 0)));
  let cvssClass = "None";
  if (maxCvss >= 7.0) cvssClass = "Critical";
  else if (maxCvss >= 4.0) cvssClass = "Medium";
  else if (maxCvss >= 0.1) cvssClass = "Low";

  const showCvssNote = maxCvss > 0 && highestSeverity !== cvssClass;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className={`mb-4 rounded-2xl bg-[#0B0D12] border border-white/5 ${borderHoverColor} ${isOpen ? glowColor : ''} transition-all duration-300 cursor-pointer overflow-hidden min-w-0 max-w-full w-full`}
    >
      {/* Group Header */}
      <div
        className="flex items-center justify-between p-6 min-w-0 overflow-hidden"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <div className={`w-1.5 h-10 rounded-full shrink-0 ${severityColor.split(' ')[0]}`}></div>
          <div className="min-w-0 flex-1 overflow-hidden">
            <h4 className="text-white font-semibold text-base mb-1 flex items-center gap-2 flex-wrap overflow-hidden">
              <span className="truncate min-w-0">{type}</span>
              <span className={`inline-flex items-center justify-center min-w-[22px] h-[22px] px-1.5 rounded-full text-[11px] font-bold bg-opacity-15 shrink-0 ${severityColor}`}>
                {count}
              </span>
            </h4>
            <p className="text-gray-500 text-sm truncate max-w-full block">
              {count === 1
                ? vulns[0].description
                : `${count} instance${count > 1 ? 's' : ''} detected \u2014 click to expand`}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {vulns[0]?.cvss_score != null && (
            <div className="hidden md:flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-bold bg-white/[0.04] border border-white/10 text-gray-300">
              <span className="text-yellow-400 font-mono">{maxCvss.toFixed(1)}</span>
              <span className="text-gray-600">|</span>
              <span className="text-cyan-400 font-mono">
                {vulns[0]?.cwe ? (
                  <a
                    href={getCweMitreUrl(vulns[0].cwe)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:underline text-cyan-400"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {vulns[0].cwe}
                  </a>
                ) : "—"}
              </span>
            </div>
          )}
          <div className={`hidden md:block px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-opacity-10 ${severityColor}`}>
            {highestSeverity}
          </div>
          <div className={`text-gray-500 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`}>
            <ChevronDown size={20} />
          </div>
        </div>
      </div>


      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            className="border-t border-white/5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 space-y-6 bg-gradient-to-b from-white/[0.01] to-transparent" style={{ overflowWrap: 'anywhere' }}>

              {/* 1. The Issue */}
              <div>
                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <AlertCircle size={14} /> The Issue
                </h5>
                <p className="text-gray-300 text-sm leading-relaxed break-words">
                  {info.why}
                </p>
                <div className="flex flex-wrap items-center gap-2 mt-3">
                  {vulns[0]?.cwe ? (
                    <a
                      href={getCweMitreUrl(vulns[0].cwe)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                    >
                      MITRE CWE Reference: {cleanCwe(vulns[0].cwe)} →
                    </a>
                  ) : (
                    <span className="text-xs text-gray-400">
                      No CWE mapping &mdash; browse MITRE:{' '}
                      <a
                        href="https://cwe.mitre.org/data/definitions/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:underline"
                      >
                        https://cwe.mitre.org/data/definitions/
                      </a>
                    </span>
                  )}

                  {vulns[0]?.cwe && (
                    <a
                      href="https://cwe.mitre.org/data/definitions/699.html"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 hover:bg-emerald-500/20 transition-colors"
                    >
                      Software Development Index (CWE-699) →
                    </a>
                  )}

                  {vulns[0]?.cvss_score != null && (
                    <span className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold border ${maxCvss >= 7.0 ? 'bg-red-500/10 border-red-500/20 text-red-300'
                        : maxCvss >= 4.0 ? 'bg-orange-500/10 border-orange-500/20 text-orange-300'
                          : maxCvss >= 0.1 ? 'bg-blue-500/10 border-blue-500/20 text-blue-300'
                            : 'bg-green-500/10 border-green-500/20 text-green-300'
                      }`}>
                      CVSS {maxCvss.toFixed(1)}
                    </span>
                  )}

                  {showCvssNote && (
                    <span className="text-gray-500 text-xs font-semibold ml-2">
                      (CVSS 3.1 classification: {cvssClass})
                    </span>
                  )}
                </div>
              </div>

              {/* 2. Recommendation */}
              <div>
                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <BookOpen size={14} /> Recommendation
                </h5>
                <div className={`rounded-lg p-4 border ${isSuggestion ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-green-500/10 border-green-500/20'}`}>
                  <p className={`${isSuggestion ? 'text-emerald-100' : 'text-green-100'} text-sm leading-relaxed break-words`}>
                    {info.fix}
                  </p>
                  <p className="text-xs text-gray-400 mt-2 pt-2 border-t border-white/[0.04]">
                    <strong>Instructions:</strong> Review the remediation instructions above. Follow development-level controls for this vulnerability class using recommendations from the <a href="https://cwe.mitre.org/data/definitions/699.html" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">CWE-699 Software Development Guidelines</a>.
                  </p>
                </div>
              </div>

              {/* 3. Evidence */}
              <div>
                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                  <Search size={14} /> Evidence
                </h5>

                <button
                  onClick={() => setShowAllInstances(!showAllInstances)}
                  className="px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-cyan-400 font-semibold hover:bg-white/10 transition flex items-center gap-1.5"
                >
                  {showAllInstances ? 'Hide ▴' : `Show all ${count} instance${count > 1 ? 's' : ''} ▾`}
                </button>

                {showAllInstances && (
                  <div className="space-y-3 mt-3">
                    {vulns.map((vuln, idx) => (
                      <div key={idx} className="bg-black/60 rounded-lg p-3 border border-white/5 font-mono text-xs text-red-300 break-all leading-relaxed overflow-x-auto max-w-full">
                        <div className="text-[10px] text-gray-500 font-bold mb-1 flex justify-between">
                          <span>Instance {idx + 1} of {count}</span>
                          <span>Source: {vuln.source ? (['nuclei', 'sqlmap', 'nikto', 'tsunami', 'nmap'].includes(vuln.source.toLowerCase()) ? vuln.source.charAt(0).toUpperCase() + vuln.source.slice(1).toLowerCase() : 'Garud') : 'Garud'}</span>
                        </div>
                        {vuln.url && (
                          <div className="text-[10px] text-cyan-500/80 mb-2 truncate">URL: {vuln.url}</div>
                        )}
                        <span className="break-all">{vuln.description}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};


const CHECKPOINTS = [
  { id: 1, name: 'Reconnaissance', icon: Globe, desc: 'Crawling & Network Scan' },
  { id: 2, name: 'Surface Analysis', icon: Search, desc: 'Headers & Input Fields' },
  { id: 3, name: 'Vulnerability Scanning', icon: AlertTriangle, desc: 'SQLi, XSS, SSRF, Crypto & More' },
  { id: 4, name: 'External Tools', icon: Terminal, desc: 'Nuclei, SQLMap, Nikto' },
  { id: 5, name: 'Final Report', icon: CheckCircle, desc: 'Aggregation & Scoring' },
];


const ScanProgressBar = ({ checkpoint, checkpointName }) => {
  const pct = Math.min((checkpoint / 5) * 100, 100);
  const done = checkpoint >= 5;
  return (
    <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${done ? 'bg-green-400' : 'bg-cyan-400 animate-pulse'}`} />
          <span className="text-sm font-semibold text-gray-300">
            {done ? 'Scan Complete' : checkpointName}
          </span>
        </div>
        <span className="text-xs font-mono text-gray-500">{Math.round(pct)}%</span>
      </div>
      <div className="relative h-1.5 bg-white/5 rounded-full overflow-hidden">
        <motion.div
          className="absolute inset-y-0 left-0 rounded-full"
          style={{ background: done ? 'linear-gradient(90deg, #10b981, #34d399)' : 'linear-gradient(90deg, #06b6d4, #8b5cf6, #d946ef)' }}
          initial={{ width: '0%' }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        />
        {!done && (
          <motion.div
            className="absolute inset-y-0 w-20 rounded-full"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent)' }}
            animate={{ x: ['-80px', '500px'] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
          />
        )}
      </div>
      <div className="flex justify-between mt-3 gap-1">
        {CHECKPOINTS.map(cp => {
          const reached = checkpoint >= cp.id;
          const active = checkpoint === cp.id - 1;
          const CpIcon = cp.icon;
          return (
            <div key={cp.id} className={`flex flex-col items-center flex-1 transition-all duration-300 ${reached ? 'opacity-100' : active ? 'opacity-60' : 'opacity-25'}`}>
              <div className={`w-8 h-8 rounded-xl flex items-center justify-center mb-1 border transition-all duration-300 ${reached ? 'bg-cyan-500/20 border-cyan-500/40' : 'bg-white/[0.02] border-white/5'}`}>
                <CpIcon size={14} className={reached ? 'text-cyan-400' : 'text-gray-600'} />
              </div>
              <span className="text-[10px] text-gray-500 text-center leading-tight hidden sm:block">{cp.name}</span>
            </div>
          );
        })}
      </div>
    </motion.div>
  );
};


const SkeletonBlock = ({ className = '' }) => (
  <div className={`animate-pulse bg-white/[0.04] rounded-2xl ${className}`} />
);
const SkeletonStatPill = () => (
  <div className="bg-[#0F1218] border border-white/5 rounded-3xl p-6 min-h-[180px] animate-pulse">
    <div className="flex justify-between items-start mb-4">
      <div className="w-12 h-12 rounded-2xl bg-white/[0.04]" />
      <div className="w-5 h-5 rounded bg-white/[0.03]" />
    </div>
    <div className="w-16 h-8 rounded bg-white/[0.06] mb-2" />
    <div className="w-24 h-4 rounded bg-white/[0.04]" />
  </div>
);
const SkeletonCard = ({ h = 'h-48' }) => (
  <div className={`${h} rounded-3xl border border-white/5 bg-[#0F1218] animate-pulse p-8`}>
    <div className="w-32 h-5 rounded bg-white/[0.06] mb-4" />
    <div className="w-full h-4 rounded bg-white/[0.04] mb-2" />
    <div className="w-3/4 h-4 rounded bg-white/[0.04]" />
  </div>
);


function App() {
  const [view, setView] = useState('landing');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [isFocused, setIsFocused] = useState(false);
  const [logs, setLogs] = useState([]);
  const [processedVulns, setProcessedVulns] = useState([]);
  const [issueCount, setIssueCount] = useState(0);
  const [riskLevel, setRiskLevel] = useState("Secure");
  const [downloadingReport, setDownloadingReport] = useState(false);


  const [checkpoint, setCheckpoint] = useState(0);
  const [checkpointName, setCheckpointName] = useState('');

  const [activeTab, setActiveTab] = useState('vulns');
  const graphRef = useRef();
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 400 });
  const [expandedNodes, setExpandedNodes] = useState(new Set());
  const [hoveredLink, setHoveredLink] = useState(null);

  useEffect(() => {
    if (scanData?.target) {
      setExpandedNodes(new Set([scanData.target]));
    }
  }, [scanData]);

  useEffect(() => {
    if (activeTab === 'graph') {
      setTimeout(() => { graphRef.current?.centerAt(0, 0, 800); }, 100);
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === 'graph' && containerRef.current) {
      const resizeObserver = new ResizeObserver((entries) => {
        for (let entry of entries) {
          const { width, height } = entry.contentRect;
          if (width > 0 && height > 0) setDimensions({ width, height });
        }
      });
      resizeObserver.observe(containerRef.current);
      return () => resizeObserver.disconnect();
    }
  }, [activeTab]);

  const groupedVulns = useMemo(() => {
    const grouped = {};
    processedVulns.forEach(function (vuln) {
      if (!grouped[vuln.type]) grouped[vuln.type] = [];
      grouped[vuln.type].push(vuln);
    });
    var entries = Object.keys(grouped).map(function (type) {
      return { type: type, vulns: grouped[type] };
    });
    entries.sort(function (a, b) {
      var aWorst = Math.min.apply(null, a.vulns.map(function (v) { return SEVERITY_ORDER[v.severity] !== undefined ? SEVERITY_ORDER[v.severity] : 99; }));
      var bWorst = Math.min.apply(null, b.vulns.map(function (v) { return SEVERITY_ORDER[v.severity] !== undefined ? SEVERITY_ORDER[v.severity] : 99; }));
      if (aWorst !== bWorst) return aWorst - bWorst;
      return b.vulns.length - a.vulns.length;
    });
    return entries;
  }, [processedVulns]);

  const displayData = useMemo(() => {
    if (!scanData?.graph_data) return { nodes: [], links: [] };
    const rootId = scanData.target;
    if (!rootId) return scanData.graph_data;
    const allNodes = scanData.graph_data.nodes;
    const allLinks = scanData.graph_data.links;


    allNodes.forEach(n => {
      delete n.fx;
      delete n.fy;
    });

    const rootNode = allNodes.find(n => cleanUrlForMatching(n.id) === cleanUrlForMatching(rootId));
    if (rootNode) {
      rootNode.fx = 0;
      rootNode.fy = 0;
    }
    const folderIds = new Set(allLinks.map(l => typeof l.source === 'object' ? l.source.id : l.source));
    const processedLinks = allLinks.map(link => {
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      const type = folderIds.has(targetId) ? 'folder_link' : 'file_link';
      return { ...link, type };
    });

    const rootNodeIdClean = rootNode ? rootNode.id : rootId;
    const FOLDER_DIST = 600;
    const FILE_DIST = 100;

    // BFS from root to assign circular layout coordinates
    const queue = [];
    if (rootNode) {
      queue.push(rootNode);
    }

    const visited = new Set();
    if (rootNodeIdClean) {
      visited.add(cleanUrlForMatching(rootNodeIdClean));
    }

    while (queue.length > 0) {
      const parent = queue.shift();
      const parentIdClean = cleanUrlForMatching(parent.id);


      const childLinks = processedLinks.filter(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        return cleanUrlForMatching(s) === parentIdClean;
      });

      if (childLinks.length > 0) {
        childLinks.forEach((link, i) => {
          const targetId = typeof link.target === 'object' ? link.target.id : link.target;
          const targetIdClean = cleanUrlForMatching(targetId);
          if (!visited.has(targetIdClean)) {
            const childNode = allNodes.find(n => cleanUrlForMatching(n.id) === targetIdClean);
            if (childNode) {
              const angle = (i / childLinks.length) * 2 * Math.PI;
              const radius = link.type === 'folder_link' ? FOLDER_DIST : FILE_DIST;
              const px = parent.fx !== undefined ? parent.fx : 0;
              const py = parent.fy !== undefined ? parent.fy : 0;
              childNode.fx = px + radius * Math.cos(angle);
              childNode.fy = py + radius * Math.sin(angle);
              queue.push(childNode);
              visited.add(targetIdClean);
            }
          }
        });
      }
    }

    return { nodes: allNodes, links: processedLinks };
  }, [scanData]);

  useEffect(() => {
    if (graphRef.current && scanData?.target) {
      try {
        const linkForce = graphRef.current.d3Force('link');
        if (linkForce) {
          linkForce.distance(link => link.type === 'folder_link' ? 600 : 100);
          linkForce.strength(link => link.type === 'folder_link' ? 0.1 : 0.9);
        }
        const chargeForce = graphRef.current.d3Force('charge');
        if (chargeForce) chargeForce.strength(-800);
        graphRef.current.d3AlphaDecay(0.02);
      } catch (e) { console.error("D3 Force Configuration Error:", e); }
    }
  }, [displayData, scanData]);

  const initialX = (window.innerWidth || 0) / 2 - LIGHT_RADIUS;
  const initialY = (window.innerHeight || 0) / 2 - LIGHT_RADIUS;
  const x = useMotionValue(initialX);
  const y = useMotionValue(initialY);
  const springConfig = { mass: 3, stiffness: 50, damping: 30 };
  const springX = useSpring(x, springConfig);
  const springY = useSpring(y, springConfig);

  useEffect(() => {
    const handleMouseMove = (e) => { x.set(e.clientX - LIGHT_RADIUS); y.set(e.clientY - LIGHT_RADIUS); };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, [x, y]);

  useEffect(() => {
    if (loading) {
      const msgs = ["Resolving Host...", "Mapping Network...", "Scanning Ports...", "Crawling HTML...", "Analyzing Headers...", "Checking XSS Vectors..."];
      let i = 0;
      const interval = setInterval(() => { if (i < msgs.length) { setLogs(prev => [...prev, msgs[i]]); i++; } }, 800);
      return () => clearInterval(interval);
    } else { setLogs([]); }
  }, [loading]);

  // Enrich vulns with CVSS/severity from CWE cache
  const _applyVulns = (allVulns, scoreResult) => {
    const enrichedVulns = allVulns.map(v => {
      const res = getCvssAndSeverity(v);
      const cwe = cleanCwe(v.cwe);
      return {
        ...v,
        cwe: cwe || undefined,
        cvss_score: res.cvss,
        severity: res.severity,
      };
    });

    const realVulns = enrichedVulns.filter(v => !SUGGESTION_TYPES.includes(v.type));
    const displayVulns = enrichedVulns.map(v =>
      SUGGESTION_TYPES.includes(v.type) ? { ...v, severity: 'Suggestion' } : v
    );

    let status;
    if (scoreResult && scoreResult.status) {

      status = scoreResult.status;
    } else {

      if (realVulns.some(v => v.severity === 'Critical')) status = "Critical";
      else if (realVulns.some(v => v.severity === 'Medium')) status = "Medium Risk";
      else if (realVulns.length > 0) status = "Warnings";
      else status = "Secure";
    }

    setProcessedVulns(displayVulns);
    setIssueCount(realVulns.length);
    setRiskLevel(status);
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;
    setLoading(true);
    setCheckpoint(0);
    setCheckpointName('Initializing...');
    setScanData(null);
    setProcessedVulns([]);
    setIssueCount(0);
    setRiskLevel("Secure");
    setView('dashboard');
    window.scrollTo(0, 0);

    let accumulatedVulns = [];

    try {
      const response = await fetch('http://127.0.0.1:7000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const evt = JSON.parse(line.slice(6));
            const cp = evt.checkpoint;
            setCheckpoint(cp);
            setCheckpointName(evt.name || '');

            if (cp === 0 && evt.error) {
              throw new Error(evt.error);
            }


            if (cp === 1) {
              setScanData(prev => ({ ...prev, target: evt.target, ip_address: evt.ip_address, endpoints_found: evt.endpoints_found, open_ports: evt.open_ports, graph_data: evt.graph_data, crawl_status: evt.crawl_status }));
            }
            if (cp === 2) {
              const newVulns = evt.vulnerabilities || [];
              accumulatedVulns = [...accumulatedVulns, ...newVulns];
              _applyVulns(accumulatedVulns);
            }
            if (cp === 3) {
              setScanData(prev => ({ ...prev, scanner_results: { ...(prev?.scanner_results || {}), ...evt.scanner_results } }));
              const newVulns = evt.vulnerabilities || [];
              accumulatedVulns = [...accumulatedVulns, ...newVulns];
              _applyVulns(accumulatedVulns);
            }
            if (cp === 4) {
              const newVulns = evt.vulnerabilities || [];
              accumulatedVulns = [...accumulatedVulns, ...newVulns];
              _applyVulns(accumulatedVulns);
            }
            if (cp === 5) {
              setScanData(prev => ({ ...prev, ...evt }));
              const finalVulns = evt.vulnerabilities || accumulatedVulns;

              const scoreResult = (evt.security_score !== undefined)
                ? { score: evt.security_score, grade: evt.security_grade, status: evt.status }
                : null;
              _applyVulns(finalVulns, scoreResult);
              setLoading(false);
            }
          } catch (parseErr) {
            console.error("SSE parse error:", parseErr);
          }
        }
      }
      if (loading) setLoading(false);
    } catch (error) {
      console.error("Backend Error:", error);
      setScanData({ target: url, ip_address: "Error", scan_duration: "0s", endpoints_found: 0, status: "Offline", open_ports: [], summary_text: "Connection to backend failed. Ensure 'server.py' is running on Port 7000.", vulnerabilities: [] });
      setIssueCount(0);
      setProcessedVulns([]);
      setRiskLevel("Offline");
      setLoading(false);
      setCheckpoint(0);
    }
  };

  const handleDownloadReport = async () => {
    if (!scanData?.target || !Array.isArray(scanData?.vulnerabilities) || downloadingReport) return;

    setDownloadingReport(true);
    try {
      const response = await fetch('http://127.0.0.1:7000/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanData),
      });

      if (!response.ok) {
        throw new Error(`Report request failed with status ${response.status}`);
      }

      const blob = await response.blob();
      const disposition = response.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="?([^"]+)"?/i);
      const filename = match ? match[1] : 'garud-report.pdf';

      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch (error) {
      console.error("Report download error:", error);
    } finally {
      setDownloadingReport(false);
    }
  };

  const goHome = () => { setView('landing'); setUrl(''); setScanData(null); setActiveTab('vulns'); setCheckpoint(0); setCheckpointName(''); setProcessedVulns([]); setIssueCount(0); setRiskLevel("Secure"); setLoading(false); window.scrollTo(0, 0); };
  const goCapabilities = () => { setView('capabilities'); window.scrollTo(0, 0); };

  return (
    <div className="min-h-screen bg-[#020408] text-gray-100 relative overflow-x-hidden font-sans selection:bg-cyan-500 selection:text-white">
      <div className="fixed inset-0 pointer-events-none opacity-[0.03] z-[60]" style={{ backgroundImage: 'url("https://grainy-gradients.vercel.app/noise.svg")' }}></div>

      <motion.div
        className="fixed rounded-full pointer-events-none"
        animate={isFocused ? "focused" : "default"}
        variants={{ default: { scale: 1, opacity: 0.6 }, focused: { scale: 0, opacity: 0 } }}
        transition={{ duration: 0.8, type: "spring", bounce: 0.3 }}
        style={{
          x: springX,
          y: springY,
          width: LIGHT_SIZE,
          height: LIGHT_SIZE,
          background: 'radial-gradient(circle, rgba(127,86,217,0.5) 0%, rgba(34,211,238,0.2) 40%, transparent 70%)',
          filter: 'blur(50px)',
          zIndex: 0
        }}
      />

      <div className="relative z-10 font-sans">
        <div className="max-w-7xl mx-auto">
          <Navbar goHome={goHome} goCapabilities={goCapabilities} activeView={view} />
        </div>
        <AnimatePresence mode="wait">
          {view === 'landing' && (
            <motion.div key="landing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, scale: 0.95, filter: 'blur(10px)' }} className="flex flex-col items-center justify-center h-[calc(100vh-120px)] overflow-hidden">
              <div className="px-4 text-center max-w-5xl mx-auto mb-12 relative flex flex-col justify-center items-center">
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-indigo-500/10 blur-[120px] rounded-full -z-10"></div>

                <h1 className="text-7xl md:text-9xl font-extrabold text-center tracking-tight mb-8 leading-[1]">
                  SECURE THE <br />
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-indigo-500">UNKNOWN</span>
                </h1>
                <p className="text-xl text-gray-400 mb-12 max-w-2xl mx-auto leading-relaxed">
                  The most advanced perimeter surveillance engine. <br />
                  Scan, analyze, and neutralize threats.
                </p>

                <div className="w-full max-w-xl mx-auto z-20">
                  <div className="relative bg-[#0B0D12] rounded-full flex items-center p-2 pl-6 shadow-2xl border border-white/10 hover:border-white/20 transition-colors duration-300">
                    <Globe className="text-gray-500 mr-4" size={20} />
                    <input type="text" placeholder="https://example.com" className="bg-transparent flex-1 outline-none text-white text-lg placeholder-gray-600" value={url} onChange={(e) => setUrl(e.target.value)} onFocus={() => setIsFocused(true)} onBlur={() => setIsFocused(false)} />
                    <button onClick={handleScan} disabled={loading} className="bg-white hover:bg-gray-100 text-black px-8 py-3 rounded-full font-bold transition-all duration-300 flex items-center gap-2">{loading ? <Activity className="animate-spin" size={20} /> : <Search size={20} />}{loading ? "Scanning" : "Scan"}</button>
                  </div>

                  {loading && (
                    <div className="mt-6 font-mono text-sm text-gray-500 text-center h-8 transition-opacity">
                      {logs.length > 0 && (
                        <span className="animate-pulse flex items-center justify-center gap-2">
                          <span className="text-cyan-400">{'>'}</span> {logs[logs.length - 1]}
                        </span>
                      )}
                    </div>
                  )}
                </div>

              </div>
            </motion.div>
          )}

          {view === 'capabilities' && (
            <motion.div key="capabilities" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="pt-8">
              <Capabilities onInitScan={goHome} />
            </motion.div>
          )}

          {view === 'dashboard' && (
            <motion.div key="dashboard" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-7xl mx-auto px-6 pb-20 pt-8">
              {/* Progress Bar — visible while scanning */}
              {loading && <ScanProgressBar checkpoint={checkpoint} checkpointName={checkpointName} />}

              <div className="flex justify-between items-end mb-10">
                <div>
                  <div className="text-gray-400 font-medium mb-1 flex items-center gap-2">
                    {loading ? <><Activity size={16} className="text-cyan-400 animate-spin" /> Scanning...</> : <><CheckCircle size={16} className="text-green-500" /> Scan Complete</>}
                  </div>
                  <h2 className="text-4xl font-bold text-white tracking-tight">{scanData?.target || url}</h2>
                </div>
                <button onClick={goHome} className="px-6 py-2 rounded-full border border-white/10 hover:bg-white/5 text-sm font-semibold transition">New Scan</button>
              </div>

              {/* Stats Row — skeleton until checkpoint 5 */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
                {checkpoint >= 5 ? (
                  <>
                    <StatPill title="Issues Found" value={issueCount} icon={AlertTriangle} color="text-orange-500" />
                    <StatPill title="Endpoints" value={scanData?.endpoints_found ?? 0} icon={Layers} color="text-blue-500" />
                    <StatPill title="Scan Duration" value={scanData?.scan_duration ?? '—'} icon={Activity} color="text-cyan-500" />
                    <StatPill title="Risk Level" value={riskLevel} icon={Shield} color={riskLevel === 'Secure' ? "text-green-500" : "text-red-500"} />
                  </>
                ) : checkpoint >= 1 ? (
                  <>
                    <StatPill title="Issues Found" value={issueCount} icon={AlertTriangle} color="text-orange-500" />
                    <StatPill title="Endpoints" value={scanData?.endpoints_found ?? '...'} icon={Layers} color="text-blue-500" />
                    <SkeletonStatPill />
                    <StatPill title="Risk Level" value={loading ? '...' : riskLevel} icon={Shield} color="text-gray-500" />
                  </>
                ) : (
                  <>{[1, 2, 3, 4].map(i => <SkeletonStatPill key={i} />)}</>
                )}
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-stretch">
                {/* Left Column: Executive Summary */}
                <div className="order-2 lg:order-1 lg:col-span-1">
                  {checkpoint >= 5 ? (
                    <ComplexCard className="h-full bg-[#0B0D12]">
                      <h3 className="text-xl font-bold text-white mb-6">Executive Summary</h3>
                      <p className="text-gray-400 leading-relaxed mb-8 text-lg">{scanData?.summary_text || 'Analyzing...'}</p>
                      {scanData?.scanner_results && (
                        <div className="mb-4 text-sm text-gray-500 space-y-1">
                          <div>SQLi findings: <span className="font-mono text-white">{scanData.scanner_results.sqli?.results?.length || 0}</span></div>
                          <div>XSS findings: <span className="font-mono text-white">{scanData.scanner_results.xss?.results?.length || 0}</span></div>
                          <div>Crypto issues: <span className="font-mono text-white">{scanData.scanner_results.cryptographic_failures?.findings?.length || 0}</span></div>
                          <div>Integrity issues: <span className="font-mono text-white">{scanData.scanner_results.integrity_failures?.findings?.length || 0}</span></div>
                          <div>Outdated components: <span className="font-mono text-white">{scanData.scanner_results.outdated_components?.vulnerabilities?.length || 0}</span></div>
                        </div>
                      )}
                      <div className="border-t border-white/5 pt-6 mt-auto">
                        <div className="flex justify-between items-center mb-3 text-sm"><span className="text-gray-500">Crawler Engine</span><span className="text-green-400 font-mono">BS4 + NMAP</span></div>
                        <button onClick={handleDownloadReport} disabled={loading || downloadingReport || !scanData?.vulnerabilities} className="w-full mt-4 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-900/40 disabled:cursor-not-allowed text-white py-3 rounded-xl font-semibold transition flex items-center justify-center gap-2"><Terminal size={18} /> {downloadingReport ? 'Generating...' : 'Download Report'}</button>
                      </div>
                    </ComplexCard>
                  ) : (
                    <SkeletonCard h="h-full" />
                  )}
                </div>

                {/* Right Column: Intelligence & Results */}
                <div className="order-1 lg:order-2 lg:col-span-2 grid gap-6 min-w-0">
                  {checkpoint >= 1 ? (
                    <ComplexCard>
                      <div className="flex justify-between items-start mb-4"><h3 className="text-xl font-bold">Network Intelligence</h3><Wifi className="text-cyan-500" size={24} /></div>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-black/40 rounded-xl border border-white/5"><div className="text-gray-400 text-xs mb-1">IP Address</div><div className="font-mono text-white text-lg break-all">{scanData?.ip_address || '...'}</div></div>
                        <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                          <div className="text-gray-400 text-xs mb-1">Open Ports</div>
                          <div className="font-mono text-white text-lg break-all">{scanData?.open_ports && scanData.open_ports.length > 0 ? scanData.open_ports.join(', ') : "None"}</div>
                        </div>
                      </div>
                    </ComplexCard>
                  ) : (
                    <SkeletonCard h="h-40" />
                  )}

                  <div className="min-w-0 overflow-hidden">
                    <div className="flex justify-between items-center mb-4">
                      <h3 className="text-xl font-bold text-white">Results</h3>
                      <div className="flex gap-2 bg-[#0B0D12] p-1 rounded-lg border border-white/5">
                        <button onClick={() => setActiveTab('vulns')} className={`px-4 py-1.5 rounded-md text-sm font-semibold transition ${activeTab === 'vulns' ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}>Vulnerabilities</button>
                        <button onClick={() => setActiveTab('graph')} className={`px-4 py-1.5 rounded-md text-sm font-semibold transition ${activeTab === 'graph' ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}>Site Map</button>
                      </div>
                    </div>

                    {activeTab === 'vulns' ? (
                      <div className="space-y-1">
                        {groupedVulns.length > 0 ? (
                          groupedVulns.map(function (group, idx) {
                            return <VulnGroup key={group.type} type={group.type} vulns={group.vulns} index={idx} />;
                          })
                        ) : (
                          <div className="p-8 bg-[#0B0D12] rounded-2xl border border-white/5 text-center text-gray-500">
                            ✓ Garud completed — no findings detected.
                          </div>
                        )}
                      </div>
                    ) : (
                      <div ref={containerRef} className="h-[500px] w-full rounded-2xl overflow-hidden border border-white/5 bg-[#0B0D12] relative group/graph">

                        {/* Enhanced Hover HUD UI */}
                        {hoveredLink && (
                          <motion.div
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            className="absolute top-4 right-4 z-20 bg-[#0F1218]/80 backdrop-blur-xl border border-cyan-500/30 p-4 rounded-2xl max-w-[320px] break-all shadow-[0_0_30px_rgba(34,211,238,0.2)] pointer-events-none"
                          >
                            <div className="flex items-center gap-2 mb-2">
                              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></div>
                              <div className="text-[10px] uppercase tracking-[0.2em] text-cyan-400 font-black">Node Intelligence</div>
                            </div>
                            <div className="text-white font-mono text-sm mb-3 leading-relaxed">{hoveredLink}</div>
                            <div className="flex gap-3">
                              <div className="px-2 py-1 rounded-md bg-white/5 border border-white/10 text-[9px] text-gray-400 font-bold uppercase">
                                Type: {hoveredLink.endsWith('/') ? 'Directory' : hoveredLink.split('.').pop().length < 5 ? hoveredLink.split('.').pop().toUpperCase() : 'Page'}
                              </div>
                              <div className="px-2 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-[9px] text-cyan-400 font-bold uppercase">
                                Status: Verified
                              </div>
                            </div>
                          </motion.div>
                        )}

                        <div className="absolute bottom-4 left-4 z-20 text-[10px] text-gray-500 uppercase tracking-widest font-bold bg-black/40 px-3 py-1.5 rounded-full border border-white/5 backdrop-blur-sm">
                          <span className="text-cyan-500 mr-2">●</span> Click nodes to expand architecture
                        </div>

                        {scanData?.graph_data && scanData.graph_data.nodes && scanData.graph_data.nodes.length > 0 ? (
                          <ForceGraph2D
                            ref={graphRef}
                            width={dimensions.width}
                            height={dimensions.height}
                            graphData={displayData}
                            nodeLabel={null}
                            nodeRelSize={10}
                            enableNodeDrag={true}
                            enableZoomInteraction={true}
                            enablePanInteraction={true}
                            d3AlphaDecay={0.02}
                            d3Force="charge"
                            d3ForceCharge={-800}
                            d3VelocityDecay={0.3}
                            linkColor={() => 'rgba(34,211,238,0.06)'}
                            backgroundColor="#0B0D12"
                            onNodeClick={() => { }}
                            onNodeHover={(node) => setHoveredLink(node ? node.id : null)}
                            onEngineStop={() => {

                            }}
                            nodeCanvasObject={(node, ctx, globalScale) => {
                              const isRoot = cleanUrlForMatching(node.id) === cleanUrlForMatching(scanData?.target);
                              const isExpanded = expandedNodes.has(node.id);


                              const hasChildren = (scanData?.graph_data?.links || []).some(l => {
                                const s = typeof l.source === 'object' ? l.source.id : l.source;
                                return s === node.id;
                              });

                              const color = node.group === 0 ? '#ff4b4b' : node.group === 1 ? '#00d4ff' : '#a78bfa';
                              const size = (isRoot ? 24 : 18) / globalScale;

                              ctx.save();
                              ctx.translate(node.x, node.y);


                              if (isRoot) {
                                const pulse = Math.sin(performance.now() / 300) * 4;
                                ctx.shadowBlur = (15 + pulse) / globalScale;
                                ctx.shadowColor = color;
                              }

                              ctx.fillStyle = color;
                              ctx.strokeStyle = isExpanded ? 'white' : 'white';
                              ctx.lineWidth = (isExpanded ? 2.5 : 1.5) / globalScale;

                              if (isRoot) {

                                ctx.beginPath();
                                for (let i = 0; i < 6; i++) {
                                  const angle = (i * Math.PI) / 3;
                                  const x = (size / 2) * Math.cos(angle);
                                  const y = (size / 2) * Math.sin(angle);
                                  if (i === 0) ctx.moveTo(x, y);
                                  else ctx.lineTo(x, y);
                                }
                                ctx.closePath();
                                ctx.fill();
                                ctx.stroke();
                              } else if (hasChildren) {

                                const w = size;
                                const h = size * 0.7;
                                ctx.beginPath();
                                ctx.roundRect(-w / 2, -h / 2, w, h, 2 / globalScale);
                                ctx.fill();
                                ctx.stroke();
                                ctx.beginPath();
                                ctx.roundRect(-w / 2, -h / 2 - 3 / globalScale, w / 2.5, 4 / globalScale, 1 / globalScale);
                                ctx.fill();
                                ctx.stroke();
                              } else {

                                const w = size * 0.75;
                                const h = size;
                                ctx.beginPath();
                                ctx.moveTo(-w / 2, -h / 2);
                                ctx.lineTo(w / 4, -h / 2);
                                ctx.lineTo(w / 2, -h / 4);
                                ctx.lineTo(w / 2, h / 2);
                                ctx.lineTo(-w / 2, h / 2);
                                ctx.closePath();
                                ctx.fill();
                                ctx.stroke();

                                ctx.beginPath();
                                ctx.moveTo(w / 4, -h / 2);
                                ctx.lineTo(w / 4, -h / 4);
                                ctx.lineTo(w / 2, -h / 4);
                                ctx.stroke();
                              }
                              ctx.restore();
                            }}
                          />
                        ) : (
                          <div className="flex items-center justify-center h-full text-gray-500">No graph data returned from the scan.</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

export default App;
