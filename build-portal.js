const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const root = __dirname;
const sourceRootMd = path.join(root, "Omar Amir — Blue Team Notes.md");
const sourceDir = path.join(root, "Omar Amir — Blue Team Notes");
const outDir = path.join(root, "blue-team-study-portal");
const pagesDir = path.join(outDir, "pages");
const jsonDir = path.join(outDir, "data", "json");
const pageJsonDir = path.join(jsonDir, "pages");
const imageDir = path.join(outDir, "assets", "images");
const attachmentDir = path.join(outDir, "assets", "attachments");

const imageExt = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg"]);
const attachmentExt = new Set([".pdf", ".csv", ".xlsx", ".docx", ".txt", ".zip", ".7z"]);
const mdLinkPattern = String.raw`\[([^\]]+)]\(([^()\n]*(?:\([^)]*\)[^()\n]*)*)\)`;
const mdImagePattern = String.raw`!\[([^\]]*)]\(([^()\n]*(?:\([^)]*\)[^()\n]*)*)\)`;
const mitreRegex = /\b(?:TA|T|S|G|M)\d{4}(?:\.\d{3})?\b/gi;

const curriculum = [
  {
    id: "l1",
    title: "SOC Level 1",
    shortTitle: "L1",
    level: "L1",
    subtitle: "Initial Triage & Fundamentals",
    description: "Foundational knowledge, standard SOC workflows, initial alert triage, and basic investigation processes.",
    sections: [
      {
        id: "l1-soc-ir-basics",
        title: "SOC & Incident Response Basics",
        topics: ["SOC Essentials", "What is Incident Response?", "Incident Response Cycle", "Frameworks", "The Hive"]
      },
      {
        id: "l1-os-command-line",
        title: "Operating System & Command Line Basics",
        topics: ["Important Windows Directories", "Windows command-line & tools", "Intro to PowerShell", "Linux CheatSheet"]
      },
      {
        id: "l1-network-web",
        title: "Networking & Web Basics",
        topics: ["Network", "Network Defenses", "Web Fundamentals"]
      },
      {
        id: "l1-initial-triage",
        title: "Initial Triage & Analysis",
        topics: ["Phishing analysis", "Phishing Analysis Labs", "OSINT"]
      },
      {
        id: "l1-tool-familiarity",
        title: "Tool Familiarity",
        topics: ["Logging Fundamentals", "SIEM", "ELK (Elastic Stack)"]
      }
    ]
  },
  {
    id: "l15",
    title: "SOC Level 1.5",
    shortTitle: "L1.5",
    level: "L1.5",
    subtitle: "Advanced Investigation & Contextualization",
    description: "Bridge topics between alert triage and deeper investigations.",
    sections: [
      {
        id: "l15-endpoint-os",
        title: "Endpoint & OS Investigation",
        topics: ["Windows Event IDs", "Windows processes", "Windows Security Monitoring", "Sysinternals", "EDR (Endpoint Detection and Response)"]
      },
      {
        id: "l15-advanced-querying",
        title: "Advanced Querying",
        topics: ["Splunk", "Splunk Filters", "Log Analysis Labs", "Regex"]
      },
      {
        id: "l15-contextual-threats",
        title: "Contextualizing Threats",
        topics: ["Threat Intelligence", "Threat Intelligence Labs", "Threat Intelligence Toolkit"]
      },
      {
        id: "l15-network-investigation",
        title: "Network Investigation",
        topics: ["Network Analysis Tools"]
      }
    ]
  },
  {
    id: "l2",
    title: "SOC Level 2",
    shortTitle: "L2",
    level: "L2",
    subtitle: "DFIR, Threat Hunting & Engineering",
    description: "Advanced investigation, forensics, threat hunting, detection engineering, and analyst tooling.",
    sections: [
      {
        id: "l2-threat-hunting",
        title: "Proactive Threat Hunting",
        topics: ["Hunting Persistence (MITRE TA0003)", "Hunting Lateral Movement (MITRE TA0008)", "Hunting Discovery (MITRE TA0007)", "Threat Hunting module", "Threat hunting Labs (SIEM)", "+100 Splunk Use Cases"]
      },
      {
        id: "l2-dfir",
        title: "Digital Forensics (DFIR)",
        topics: ["Digital Forensics", "Windows Forensics", "Forensics Labs", "Memory forensics", "Memory Forensics Labs", "Volatility", "Linux Artifacts & Forensic Evidence Collection", "Stenography"]
      },
      {
        id: "l2-attack-vectors",
        title: "Advanced Attack Vectors & Internals",
        topics: ["Active Directory", "Kerberos authentication", "Detecting AD Attacks", "Detecting Active Directory Attacks / HTB", "Windows Internals", "Command-and-Control (C2)", "Command-and-Control (C2) Evasion Techniques", "Detecting Web Attacks", "Network Analysis Labs"]
      },
      {
        id: "l2-detection-engineering",
        title: "Detection Engineering & Automation",
        topics: ["Detection Engineering", "Sigma", "Yara", "Atomic Red Team", "Threat Modelling", "AD Hardening"]
      },
      {
        id: "l2-scripting-tooling",
        title: "Advanced Scripting & Analysis Tooling",
        topics: ["PowerShell for Incident Response", "Powershell Detection", "PowerShell Logs", "LOLBins (living-off-the-land binaries)", "Osquery", "Cryptography"]
      }
    ]
  }
];

const l15Hints = [
  "threat hunting",
  "hunting ",
  "persistence",
  "advanced powershell",
  "powershell detection",
  "powershell logs",
  "powerShell for incident response".toLowerCase(),
  "edr investigation",
  "splunk correlation",
  "correlation",
  "detection engineering",
  "dfir",
  "digital forensics",
  "memory forensics",
  "forensic evidence",
  "lateral movement",
  "active directory attack",
  "golden ticket",
  "silver ticket",
  "kerberoast",
  "dcsync",
  "dcshadow",
  "lolbins",
  "command-and-control",
  "c2",
  "atomic red team",
  "incident response cycle"
];

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function cleanDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  ensureDir(dir);
}

function walk(dir) {
  const output = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) output.push(...walk(full));
    else output.push(full);
  }
  return output;
}

function readUtf8(file) {
  return fs.readFileSync(file, "utf8").replace(/^\uFEFF/, "");
}

function hash(value) {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 8);
}

function slugify(value) {
  return String(value)
    .normalize("NFKD")
    .replace(/[^\w\s.-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .toLowerCase()
    .slice(0, 90) || "untitled";
}

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function attrEscape(value) {
  return htmlEscape(value).replace(/'/g, "&#39;");
}

function decodeEntities(value) {
  let out = String(value);
  for (let i = 0; i < 3; i += 1) {
    out = out
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }
  return out;
}

function stripMd(value) {
  return String(value)
    .replace(new RegExp(mdImagePattern, "g"), "")
    .replace(new RegExp(mdLinkPattern, "g"), "$1")
    .replace(/[*_~`>#]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function relFromSource(file) {
  return path.relative(sourceDir, file).replace(/\\/g, "/");
}

function titleFromFile(file) {
  return path.basename(file, ".md").trim() || "Untitled";
}

function normalizeName(value) {
  return stripMd(decodeEntities(decodeURIComponent(String(value))))
    .replace(/\.md$/i, "")
    .replace(/\?/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function resolveLocalRef(ref, fromFile) {
  let clean = decodeEntities(decodeURIComponent(String(ref))).replace(/\+/g, " ");
  if (/^[a-z]+:/i.test(clean) || clean.startsWith("#")) return null;
  clean = clean.replace(/(\.md)#.*$/i, "$1");
  return path.resolve(path.dirname(fromFile), clean);
}

function parseMarkdownLinks(markdown, fromFile) {
  const links = [];
  const re = new RegExp(mdLinkPattern, "g");
  let match;
  while ((match = re.exec(markdown))) {
    const ref = match[2];
    const local = resolveLocalRef(ref, fromFile);
    links.push({
      label: stripMd(match[1]),
      href: ref,
      local,
      isMarkdown: Boolean(local && path.extname(local).toLowerCase() === ".md")
    });
  }
  return links;
}

function parseRootLinks() {
  if (!fs.existsSync(sourceRootMd)) return [];
  return parseMarkdownLinks(readUtf8(sourceRootMd), sourceRootMd)
    .filter((link) => link.isMarkdown)
    .map((link) => ({ label: link.label, local: link.local }));
}

function extractBlocks(markdown) {
  const headings = [];
  const codeBlocks = [];
  const quotes = [];
  const checklists = [];
  const lines = markdown.split(/\r?\n/);
  let inCode = false;
  let lang = "";
  let code = [];
  for (const line of lines) {
    const fence = line.match(/^```+\s*([\w#+.-]*)/);
    if (fence) {
      if (inCode) {
        codeBlocks.push({ language: lang || "text", code: code.join("\n") });
        code = [];
        lang = "";
      } else {
        lang = fence[1] || "text";
      }
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) headings.push({ level: heading[1].length, text: stripMd(heading[2]) });
    if (/^\s*[-*]\s+\[[ xX]]\s+/.test(line)) checklists.push(stripMd(line));
    if (/^\s*>/.test(line)) quotes.push(stripMd(line.replace(/^\s*>\s?/, "")));
  }
  return { headings, codeBlocks, quotes, checklists };
}

function firstParagraph(markdown) {
  const clean = markdown.replace(/```[\s\S]*?```/g, "");
  for (const block of clean.split(/\n\s*\n/)) {
    const text = stripMd(block);
    if (text.length > 50 && !/\.md\b/i.test(text)) return text.slice(0, 360);
  }
  return "Converted from the original Notion export and preserved as part of the Blue Team Study Portal.";
}

function copyAssets(allFiles) {
  const imageMap = new Map();
  const attachmentMap = new Map();
  for (const file of allFiles) {
    const ext = path.extname(file).toLowerCase();
    if (!imageExt.has(ext) && !attachmentExt.has(ext)) continue;
    const rel = relFromSource(file);
    const unique = `${slugify(path.dirname(rel))}-${slugify(path.basename(file, ext))}-${hash(rel)}${ext}`.replace(/^-/, "");
    if (imageExt.has(ext)) {
      fs.copyFileSync(file, path.join(imageDir, unique));
      imageMap.set(path.resolve(file), `../assets/images/${unique}`);
    } else {
      fs.copyFileSync(file, path.join(attachmentDir, unique));
      attachmentMap.set(path.resolve(file), `../assets/attachments/${unique}`);
    }
  }
  return { imageMap, attachmentMap };
}

function inlineMd(value, file, maps, pathToSlug) {
  let text = htmlEscape(value);
  text = text.replace(new RegExp(mdImagePattern, "g"), (all, alt, ref) => {
    if (/^https?:/i.test(ref)) {
      return `<a class="external-asset" href="${attrEscape(ref)}">External image reference: ${htmlEscape(stripMd(alt || ref))}</a>`;
    }
    const local = resolveLocalRef(ref, file);
    const src = local && maps.imageMap.has(path.resolve(local)) ? maps.imageMap.get(path.resolve(local)) : attrEscape(ref);
    return `<button class="image-button" data-src="${attrEscape(src)}" data-alt="${attrEscape(stripMd(alt))}"><img src="${attrEscape(src)}" alt="${attrEscape(stripMd(alt))}" loading="lazy"></button>`;
  });
  text = text.replace(new RegExp(mdLinkPattern, "g"), (all, label, ref) => {
    const local = resolveLocalRef(ref, file);
    if (local && path.extname(local).toLowerCase() === ".md") {
      const slug = pathToSlug.get(path.resolve(local));
      if (slug) return `<a class="note-link" href="${slug}.html">${inlineMd(label, file, maps, pathToSlug)}</a>`;
    }
    if (local && maps.attachmentMap.has(path.resolve(local))) {
      return `<a class="note-link" href="${attrEscape(maps.attachmentMap.get(path.resolve(local)))}">${inlineMd(label, file, maps, pathToSlug)}</a>`;
    }
    return `<a class="note-link" href="${attrEscape(ref)}">${inlineMd(label, file, maps, pathToSlug)}</a>`;
  });
  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  return text;
}

function renderMarkdown(markdown, file, maps, pathToSlug) {
  const html = [];
  const lines = markdown.split(/\r?\n/);
  let paragraph = [];
  let lists = [];
  let inCode = false;
  let lang = "text";
  let code = [];

  const closeParagraph = () => {
    if (!paragraph.length) return;
    html.push(`<p>${inlineMd(paragraph.join(" "), file, maps, pathToSlug)}</p>`);
    paragraph = [];
  };
  const closeLists = (to = 0) => {
    while (lists.length > to) html.push(`</${lists.pop()}>`);
  };
  const tableHtml = (rows) => {
    const cells = rows.map((row) => row.trim().replace(/^\||\|$/g, "").split("|").map((c) => inlineMd(c.trim(), file, maps, pathToSlug)));
    const head = cells[0] || [];
    const body = cells.slice(2);
    return `<div class="table-wrap"><table><thead><tr>${head.map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>${body.map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const fence = line.match(/^```+\s*([\w#+.-]*)/);
    if (fence) {
      closeParagraph();
      closeLists();
      if (inCode) {
        html.push(`<div class="code-shell"><div class="code-bar"><span>${htmlEscape(lang)}</span><button class="copy-code" type="button">Copy</button></div><pre><code class="language-${attrEscape(lang)}">${htmlEscape(code.join("\n"))}</code></pre></div>`);
        code = [];
        lang = "text";
      } else {
        lang = fence[1] || "text";
      }
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    if (!line.trim()) {
      closeParagraph();
      closeLists();
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      closeParagraph();
      closeLists();
      const level = Math.min(6, heading[1].length + 1);
      const text = stripMd(heading[2]);
      html.push(`<h${level} id="${slugify(text)}">${inlineMd(heading[2], file, maps, pathToSlug)}</h${level}>`);
      continue;
    }
    if (/^\s*\|.+\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{3,}:?\s*\|/.test(lines[i + 1])) {
      closeParagraph();
      closeLists();
      const rows = [];
      while (i < lines.length && /^\s*\|.+\|\s*$/.test(lines[i])) rows.push(lines[i++]);
      i -= 1;
      html.push(tableHtml(rows));
      continue;
    }
    const quote = line.match(/^\s*>\s?(.*)$/);
    if (quote) {
      closeParagraph();
      closeLists();
      html.push(`<blockquote>${inlineMd(quote[1], file, maps, pathToSlug)}</blockquote>`);
      continue;
    }
    const bullet = line.match(/^(\s*)[-*+]\s+(.+)$/);
    const ordered = line.match(/^(\s*)\d+\.\s+(.+)$/);
    if (bullet || ordered) {
      closeParagraph();
      const content = bullet ? bullet[2] : ordered[2];
      const type = bullet ? "ul" : "ol";
      const depth = Math.floor((bullet ? bullet[1] : ordered[1]).replace(/\t/g, "    ").length / 4) + 1;
      while (lists.length < depth) {
        html.push(`<${type}>`);
        lists.push(type);
      }
      closeLists(depth);
      const task = content.match(/^\[([ xX])]\s+(.+)$/);
      const item = task
        ? `<label class="task"><input type="checkbox" disabled ${task[1].toLowerCase() === "x" ? "checked" : ""}>${inlineMd(task[2], file, maps, pathToSlug)}</label>`
        : inlineMd(content, file, maps, pathToSlug);
      html.push(`<li>${item}</li>`);
      continue;
    }
    if (/^---+$/.test(line.trim())) {
      closeParagraph();
      closeLists();
      html.push("<hr>");
      continue;
    }
    paragraph.push(line.trim());
  }
  closeParagraph();
  closeLists();
  return html.join("\n");
}

function classifyLevel(title, relPath, markdown) {
  const hay = `${title} ${relPath} ${markdown.slice(0, 5000)}`.toLowerCase();
  return l15Hints.some((hint) => hay.includes(hint)) ? "L1.5" : "L1";
}

function deriveTags(title, relPath, markdown) {
  const hay = `${title} ${relPath} ${markdown}`.toLowerCase();
  const pairs = [
    ["splunk", "Splunk"],
    ["siem", "SIEM"],
    ["edr", "EDR"],
    ["powershell", "PowerShell"],
    ["windows", "Windows"],
    ["linux", "Linux"],
    ["sysmon", "Sysmon"],
    ["phishing", "Phishing"],
    ["network", "Network"],
    ["active directory", "Active Directory"],
    ["kerberos", "Kerberos"],
    ["web", "Web"],
    ["forensic", "DFIR"],
    ["memory", "Memory"],
    ["detection", "Detection"],
    ["threat intelligence", "Threat Intel"],
    ["osint", "OSINT"],
    ["incident response", "Incident Response"],
    ["persistence", "Persistence"],
    ["lateral movement", "Lateral Movement"],
    ["command-and-control", "C2"],
    ["c2", "C2"],
    ["yara", "YARA"],
    ["sigma", "Sigma"]
  ];
  return [...new Set(pairs.filter(([key]) => hay.includes(key)).map(([, label]) => label))].slice(0, 10);
}

function findTopicByLabel(label, nodes) {
  const norm = normalizeName(label.replace(/\s*\([^)]*\)\s*/g, " "));
  const exact = nodes.find((node) => normalizeName(node.title) === norm);
  if (exact) return exact;
  if (norm === "the hive") return nodes.find((node) => normalizeName(node.title) === "the hive");
  if (norm === "edr") return nodes.find((node) => normalizeName(node.title).startsWith("edr"));
  const compact = norm.replace(/[^a-z0-9]+/g, "");
  const compactCandidates = nodes
    .map((node) => ({ node, compactTitle: normalizeName(node.title).replace(/[^a-z0-9]+/g, "") }))
    .filter((item) => item.compactTitle.includes(compact))
    .sort((a, b) => a.compactTitle.length - b.compactTitle.length);
  const compactMatch = compactCandidates[0]?.node;
  if (compactMatch) return compactMatch;
  const tokens = norm.split(/[^a-z0-9]+/).filter((token) => token.length > 1);
  return nodes.find((node) => {
    const title = normalizeName(node.title);
    return tokens.every((token) => title.includes(token));
  });
}

function ancestors(node, byId) {
  const out = [];
  let current = node;
  while (current && current.parentId) {
    current = byId.get(current.parentId);
    if (current) out.unshift(current);
  }
  return out;
}

function topRoot(node, byId) {
  let current = node;
  while (current.parentId && byId.get(current.parentId)) current = byId.get(current.parentId);
  return current;
}

function flattenTree(node, byId) {
  const out = [node];
  for (const childId of node.children) out.push(...flattenTree(byId.get(childId), byId));
  return out;
}

function nodeToNav(node, byId) {
  return {
    id: node.id,
    title: node.title,
    slug: node.slug,
    level: node.level,
    curriculumLevelId: node.curriculumLevelId || null,
    curriculumSectionId: node.curriculumSectionId || null,
    curriculumSectionTitle: node.curriculumSectionTitle || null,
    tags: node.tags,
    mitre: node.mitre,
    relPath: node.relPath,
    children: node.children.map((id) => nodeToNav(byId.get(id), byId))
  };
}

function buildStudy(node) {
  const concepts = node.headings.map((h) => h.text).filter(Boolean).slice(0, 12);
  const splunkExamples = node.codeBlocks.filter((b) => /index=|sourcetype=|\|\s*(stats|table|where|eval|rex|timechart)/i.test(b.code)).slice(0, 4);
  const commands = node.codeBlocks.filter((b) => /(powershell|cmd|bash|shell|text)/i.test(b.language) || /\b(Get-|Set-|net|reg|wevtutil|tasklist|wmic|curl|grep|findstr|volatility|yara|sigma)\b/i.test(b.code)).slice(0, 5);
  const tools = ["Splunk", "SIEM", "EDR", "Sysmon", "PowerShell", "Wireshark", "Zeek", "Volatility", "YARA", "Sigma", "Osquery", "TheHive"]
    .filter((tool) => `${node.title} ${node.raw}`.toLowerCase().includes(tool.toLowerCase()));
  return {
    overview: node.overview,
    whySoc: "Use this note as an analyst reference: understand the concept, identify the relevant telemetry, pivot through evidence, and document the decision path clearly.",
    keyConcepts: concepts,
    workflow: [
      "Identify the user, host, process, network flow, or identity object involved.",
      "Collect the highest-value logs first and preserve timestamps and assumptions.",
      "Pivot through related notes, telemetry sources, and MITRE references.",
      "Document findings, gaps, containment options, and detection improvements."
    ],
    splunkExamples,
    importantCommands: commands,
    tools,
    tips: node.quotes.filter(Boolean).slice(0, 6)
  };
}

function renderTree(node, byId, currentId, depth = 0) {
  const active = node.id === currentId;
  const hasChildren = node.children.length > 0;
  const children = hasChildren ? `<div class="tree-children">${node.children.map((id) => renderTree(byId.get(id), byId, currentId, depth + 1)).join("")}</div>` : "";
  return `<details class="tree-node" ${depth < 2 || active ? "open" : ""}>
    <summary>
      <a class="${active ? "active" : ""}" href="${node.slug}.html"><span>${htmlEscape(node.title)}</span><em>${node.level}</em></a>
      ${hasChildren ? `<b>${node.children.length}</b>` : ""}
    </summary>
    ${children}
  </details>`;
}

function sidebar(nav, currentSlug = "", prefix = "../") {
  const topicLink = (item) => item.node
    ? `<a class="side-link ${item.node.slug === currentSlug ? "active" : ""}" href="${prefix}pages/${item.node.slug}.html"><span>${htmlEscape(item.label)}</span><em>${item.node.children} nodes</em></a>`
    : `<span class="side-link missing">${htmlEscape(item.label)}</span>`;
  const sectionDrawer = (section) => `<details class="side-section"><summary>${htmlEscape(section.title)}<span>${section.topics.length}</span></summary>${section.topics.map(topicLink).join("")}</details>`;
  const levelDrawer = (level, index) => `<details class="side-level" ${index === 0 ? "open" : ""}><summary><strong>${htmlEscape(level.shortTitle)}</strong><span>${htmlEscape(level.subtitle)}</span></summary>${level.sections.map(sectionDrawer).join("")}</details>`;
  return `<aside class="sidebar">
    <a class="brand" href="${prefix}index.html"><span>BT</span><strong>Blue Team Study Portal</strong></a>
    <button class="command-button" type="button" id="openCommand">Search / Quick jump <kbd>Ctrl K</kbd></button>
    <label class="search-box"><span>Search notes</span><input id="globalSearch" type="search" placeholder="Search MITRE, commands, topics"></label>
    <div id="searchResults" class="search-results" hidden></div>
    <nav>${nav.levels.map(levelDrawer).join("")}</nav>
  </aside>`;
}

function shell(title, body, nav, currentSlug = "", prefix = "../") {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>${htmlEscape(title)} | Blue Team Study Portal</title>
  <link rel="stylesheet" href="${prefix}style.css">
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 antialiased">
  <div class="app-shell">
    ${sidebar(nav, currentSlug, prefix)}
    <main class="content">${body}</main>
  </div>
  <div class="lightbox" id="lightbox" hidden><button type="button" aria-label="Close image">×</button><img alt=""></div>
  <div class="command-palette" id="commandPalette" hidden>
    <div class="command-panel">
      <div class="command-head"><strong>Quick jump</strong><button type="button" id="closeCommand">Close</button></div>
      <input id="commandInput" type="search" placeholder="Search any note, tag, command, or MITRE ID">
      <div id="commandResults" class="command-results"></div>
    </div>
  </div>
  <script src="${prefix}data/json/search-index.js"></script>
  <script src="${prefix}script.js"></script>
</body>
</html>`;
}

function renderStudy(study) {
  const list = (items) => items && items.length ? `<ul>${items.map((item) => `<li>${htmlEscape(item)}</li>`).join("")}</ul>` : `<p class="muted">No extracted items for this section.</p>`;
  const codeList = (items) => items && items.length ? items.map((b) => `<div class="code-shell"><div class="code-bar"><span>${htmlEscape(b.language)}</span><button class="copy-code" type="button">Copy</button></div><pre><code>${htmlEscape(b.code)}</code></pre></div>`).join("") : `<p class="muted">No direct examples extracted.</p>`;
  return `<section class="study-grid">
    <article><h2>Overview</h2><p>${htmlEscape(study.overview)}</p></article>
    <article><h2>Why It Matters In SOC</h2><p>${htmlEscape(study.whySoc)}</p></article>
    <article><h2>Key Concepts</h2>${list(study.keyConcepts)}</article>
    <article><h2>Analyst Workflow</h2>${list(study.workflow)}</article>
    <article><h2>Splunk/SIEM Examples</h2>${codeList(study.splunkExamples)}</article>
    <article><h2>Important Commands</h2>${codeList(study.importantCommands)}</article>
    <article><h2>Tools Used</h2>${list(study.tools)}</article>
    <article><h2>Notes/Tips</h2>${list(study.tips)}</article>
  </section>`;
}

function renderTopic(node, byId, nav, ordered) {
  const rootNode = topRoot(node, byId);
  const chain = [...ancestors(node, byId), node];
  const flatRoot = flattenTree(rootNode, byId);
  const rootIndex = flatRoot.findIndex((item) => item.id === node.id);
  const prev = rootIndex > 0 ? flatRoot[rootIndex - 1] : ordered[ordered.findIndex((item) => item.id === node.id) - 1];
  const next = rootIndex < flatRoot.length - 1 ? flatRoot[rootIndex + 1] : ordered[ordered.findIndex((item) => item.id === node.id) + 1];
  const related = node.relatedLinks.length ? `<section class="related"><h2>Related Notes</h2>${node.relatedLinks.slice(0, 12).map((id) => {
    const item = byId.get(id);
    return item ? `<a href="${item.slug}.html">${htmlEscape(item.title)}<span>${htmlEscape(item.level)}</span></a>` : "";
  }).join("")}</section>` : "";
  const children = node.children.length ? `<section class="content-cards"><h2>Nested Structure</h2><div>${node.children.map((id) => {
    const child = byId.get(id);
    return `<a class="content-card" href="${child.slug}.html"><strong>${htmlEscape(child.title)}</strong><span>${htmlEscape(child.overview)}</span><em>${child.children.length} child notes</em></a>`;
  }).join("")}</div></section>` : "";
  const tags = [...node.tags.map((t) => `<span class="tag">${htmlEscape(t)}</span>`), ...node.mitre.map((t) => `<span class="tag mitre">${htmlEscape(t)}</span>`)].join("");
  const toc = node.headings.length ? `<details class="toc" open><summary>Table of contents</summary>${node.headings.slice(0, 40).map((h) => `<a href="#${slugify(h.text)}">${htmlEscape(h.text)}</a>`).join("")}</details>` : "";
  const breadcrumbs = chain.map((item, index) => index === chain.length - 1 ? `<span>${htmlEscape(item.title)}</span>` : `<a href="${item.slug}.html">${htmlEscape(item.title)}</a>`).join("<span>/</span>");
  const body = `<header class="topic-hero">
      <div class="breadcrumbs"><a href="../index.html">Home</a><span>/</span>${breadcrumbs}</div>
      <h1>${htmlEscape(node.title)}</h1>
      <p>${htmlEscape(node.overview)}</p>
      <div class="tag-row"><span class="tag level">${node.level}</span>${tags}</div>
    </header>
    <div class="reader-layout">
      <aside class="secondary-nav">
        <div class="secondary-heading"><span>Current Tree</span><strong>${htmlEscape(rootNode.title)}</strong></div>
        ${renderTree(rootNode, byId, node.id)}
      </aside>
      <article class="reader">
        ${children}
        ${renderStudy(node.study)}
        <section class="source-note"><h2>Original Notes</h2>${node.html}</section>
      </article>
      ${toc}
    </div>
    ${related}
    <footer class="pager">${prev ? `<a href="${prev.slug}.html">← ${htmlEscape(prev.title)}</a>` : "<span></span>"}${next ? `<a href="${next.slug}.html">${htmlEscape(next.title)} →</a>` : "<span></span>"}</footer>`;
  return shell(node.title, body, nav, node.slug, "../");
}

function renderIndex(nav, nodes, stats) {
  const topicCard = (item) => item.node ? `<a class="home-card" href="pages/${item.node.slug}.html"><strong>${htmlEscape(item.label)}</strong><span>${htmlEscape(item.node.overview)}</span><em>${item.node.children} nested notes</em></a>` : `<div class="home-card missing"><strong>${htmlEscape(item.label)}</strong><span>Source note not found in export.</span></div>`;
  const levelBands = nav.levels.map((level) => `<section class="level-band" id="${level.id}">
    <div class="level-head"><span>${htmlEscape(level.shortTitle)}</span><h2>${htmlEscape(level.title)}</h2><p>${htmlEscape(level.subtitle)}. ${htmlEscape(level.description)}</p></div>
    ${level.sections.map((section) => `<details class="category-band" id="${section.id}" open><summary><h3>${htmlEscape(section.title)}</h3><span>${section.topics.length} topics</span></summary><div class="home-grid">${section.topics.map(topicCard).join("")}</div></details>`).join("")}
  </section>`).join("");
  const body = `<header class="home-hero">
      <div><p class="eyebrow">Offline SOC Knowledge Base</p><h1>Blue Team Study Portal</h1><p>A production-ready cybersecurity documentation portal with clear L1, L1.5, and L2 learning tracks while preserving the original Notion note hierarchy.</p></div>
      <div class="stats-panel"><strong>${stats.pages}</strong><span>notes</span><strong>${stats.images}</strong><span>images</span><strong>${stats.mitre}</strong><span>MITRE refs</span></div>
    </header>
    <section class="quick-nav">${nav.levels.map((level) => `<a href="#${level.id}"><strong>${htmlEscape(level.shortTitle)}</strong><span>${htmlEscape(level.subtitle)}</span></a>`).join("")}</section>
    ${levelBands}`;
  return shell("Home", body, nav, "", "");
}

function writeCss() {
  fs.writeFileSync(path.join(outDir, "style.css"), `/* Self-contained TailwindCSS-style compiled utility and component layer. No CDN or build server required. */
:root{--bg:#020617;--bg2:#08111f;--panel:rgba(15,23,42,.78);--panel2:rgba(30,41,59,.78);--line:rgba(148,163,184,.18);--text:#e5eefb;--muted:#94a3b8;--cyan:#22d3ee;--emerald:#34d399;--violet:#a78bfa;--amber:#fbbf24;--rose:#fb7185;--shadow:0 24px 80px rgba(0,0,0,.38);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 20% -10%,rgba(34,211,238,.16),transparent 28rem),radial-gradient(circle at 90% 0,rgba(167,139,250,.12),transparent 30rem),linear-gradient(180deg,var(--bg),#050b17 55%,#020617);color:var(--text);line-height:1.65}.min-h-screen{min-height:100vh}.bg-slate-950{background-color:#020617}.text-slate-100{color:#f1f5f9}.antialiased{-webkit-font-smoothing:antialiased}a{color:inherit}.app-shell{display:grid;grid-template-columns:310px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;overflow:auto;padding:22px 16px;border-right:1px solid var(--line);background:rgba(2,6,23,.86);backdrop-filter:blur(18px)}.brand{display:flex;align-items:center;gap:12px;text-decoration:none;margin-bottom:22px}.brand span{display:grid;place-items:center;width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,rgba(34,211,238,.22),rgba(52,211,153,.16));border:1px solid rgba(34,211,238,.35);color:var(--cyan);font-weight:900}.brand strong{font-size:15px}.search-box{display:grid;gap:8px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}.search-box input{width:100%;border:1px solid var(--line);border-radius:12px;background:rgba(15,23,42,.9);color:var(--text);padding:12px 13px;outline:0}.search-box input:focus{border-color:var(--cyan);box-shadow:0 0 0 4px rgba(34,211,238,.12)}.search-results{border:1px solid var(--line);border-radius:12px;background:#0f172a;margin-bottom:14px;overflow:hidden}.search-results a{display:block;padding:10px 12px;text-decoration:none;border-bottom:1px solid var(--line)}.search-results a:hover,.side-link:hover{background:rgba(34,211,238,.08)}.side-drawer{border-top:1px solid var(--line);padding:10px 0}.side-drawer summary{display:flex;align-items:center;justify-content:space-between;cursor:pointer;font-weight:800;color:#f8fafc}.side-drawer summary span{font-size:12px;color:var(--cyan)}.side-link{display:flex;justify-content:space-between;gap:10px;align-items:center;text-decoration:none;margin:5px 0;padding:9px 10px;border-radius:10px;color:#cbd5e1;font-size:14px}.side-link span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.side-link em{font-style:normal;font-size:11px;color:var(--muted)}.side-link.active{background:linear-gradient(90deg,rgba(34,211,238,.2),rgba(52,211,153,.08));box-shadow:inset 3px 0 0 var(--cyan);color:#fff}.missing{opacity:.45}.content{min-width:0;padding:30px clamp(18px,4vw,54px) 56px}.home-hero,.topic-hero{display:flex;justify-content:space-between;gap:28px;padding:32px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(135deg,rgba(15,23,42,.86),rgba(8,47,73,.54));box-shadow:var(--shadow)}.home-hero h1,.topic-hero h1{font-size:clamp(36px,6vw,76px);line-height:1;margin:4px 0 14px;letter-spacing:0}.home-hero p,.topic-hero p{max-width:860px;color:#cbd5e1;font-size:18px}.eyebrow,.breadcrumbs{color:var(--cyan);font-size:12px;text-transform:uppercase;letter-spacing:.12em}.breadcrumbs{display:flex;gap:8px;flex-wrap:wrap}.breadcrumbs a{text-decoration:none;color:#a5f3fc}.stats-panel{display:grid;grid-template-columns:auto 1fr;gap:8px 14px;align-self:center;min-width:190px;padding:18px;border:1px solid var(--line);border-radius:18px;background:rgba(2,6,23,.38)}.stats-panel strong{font-size:34px;color:var(--emerald)}.stats-panel span{align-self:center;color:var(--muted)}.quick-nav,.home-grid,.content-cards>div{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.quick-nav{margin:22px 0}.quick-nav a,.home-card,.content-card,.study-grid article{display:grid;gap:7px;text-decoration:none;padding:16px;border:1px solid var(--line);border-radius:18px;background:var(--panel);box-shadow:0 14px 32px rgba(0,0,0,.12)}.quick-nav a:hover,.home-card:hover,.content-card:hover{border-color:rgba(34,211,238,.58);transform:translateY(-1px)}.quick-nav span,.home-card span,.content-card span,.muted{color:var(--muted)}.home-card em,.content-card em{color:var(--emerald);font-style:normal;font-size:13px}.category-band{padding:30px 0;border-top:1px solid var(--line)}.category-head{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:14px}.category-head h2,.content-cards h2,.study-grid h2,.related h2{margin:0;color:#fff}.category-head span{color:var(--cyan)}.tag-row{display:flex;flex-wrap:wrap;gap:8px}.tag{display:inline-flex;align-items:center;min-height:28px;padding:4px 10px;border:1px solid var(--line);border-radius:999px;background:rgba(15,23,42,.86);font-size:12px;color:#dbeafe}.tag.level{border-color:rgba(34,211,238,.7);color:#a5f3fc}.tag.mitre{border-color:rgba(251,191,36,.72);color:#fde68a}.reader-layout{display:grid;grid-template-columns:280px minmax(0,1fr) 220px;gap:22px;margin-top:24px;align-items:start}.secondary-nav,.toc{position:sticky;top:20px;max-height:calc(100vh - 40px);overflow:auto;border:1px solid var(--line);border-radius:18px;background:rgba(2,6,23,.52);padding:14px}.secondary-heading{display:grid;gap:2px;margin-bottom:8px}.secondary-heading span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.tree-node{margin:4px 0}.tree-node summary{list-style:none;display:flex;align-items:center;gap:6px}.tree-node summary::-webkit-details-marker{display:none}.tree-node summary a{flex:1;display:flex;justify-content:space-between;gap:10px;text-decoration:none;padding:7px 8px;border-radius:10px;color:#cbd5e1;font-size:13px}.tree-node summary a.active{background:rgba(34,211,238,.16);color:#fff}.tree-node summary a span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tree-node summary a em{font-style:normal;color:var(--muted);font-size:11px}.tree-node summary b{font-size:10px;color:var(--cyan);font-weight:700}.tree-children{margin-left:13px;border-left:1px solid var(--line);padding-left:8px}.reader{min-width:0}.study-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin:22px 0}.study-grid article{display:block}.study-grid h2{font-size:17px;margin-bottom:8px}.source-note{padding:22px 0;max-width:1050px}.source-note h2{font-size:30px;margin:28px 0 14px}.source-note h3{font-size:24px;margin:28px 0 10px}.source-note h4{font-size:20px;margin:22px 0 8px}.source-note h5,.source-note h6{font-size:16px;margin:18px 0 8px}.source-note p,.source-note li{color:#dbe4f0}.source-note code:not(pre code){background:#111827;border:1px solid var(--line);border-radius:6px;padding:1px 5px;color:#a7f3d0}.source-note blockquote{margin:18px 0;padding:13px 15px;border-left:4px solid var(--cyan);background:rgba(8,47,73,.25);border-radius:0 12px 12px 0}.source-note hr{border:0;border-top:1px solid var(--line);margin:26px 0}.note-link{color:#67e8f9;text-decoration:none}.note-link:hover{text-decoration:underline}.external-asset{display:block;margin:14px 0;padding:12px 14px;border:1px dashed var(--amber);border-radius:12px;color:#fde68a;background:rgba(251,191,36,.08);text-decoration:none}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px;margin:18px 0}table{width:100%;border-collapse:collapse;min-width:560px}th,td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#0f172a;text-align:left;color:#fff}.code-shell{margin:14px 0;border:1px solid rgba(34,211,238,.22);border-radius:14px;background:#020617;overflow:hidden}.code-bar{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#0f172a;color:var(--muted);font-size:12px}.copy-code{border:1px solid var(--line);border-radius:9px;background:#172033;color:var(--text);padding:5px 9px;cursor:pointer}.copy-code:hover{border-color:var(--cyan)}pre{margin:0;overflow:auto;padding:16px}pre code{font-family:"Cascadia Code","Fira Code",Consolas,monospace;font-size:13px;color:#e2e8f0}.tok-key{color:#93c5fd}.tok-str{color:#fcd34d}.tok-cmd{color:#5eead4}.image-button{display:block;max-width:100%;padding:0;border:1px solid var(--line);border-radius:16px;background:#020617;cursor:zoom-in;margin:16px 0;overflow:hidden}.image-button img{display:block;max-width:100%;height:auto}.task{display:flex;gap:9px;align-items:flex-start}.toc summary{cursor:pointer;font-weight:800;color:#fff}.toc a{display:block;text-decoration:none;color:var(--muted);font-size:13px;margin-top:8px}.toc a:hover{color:#fff}.related{margin:24px 0;padding:18px;border:1px solid var(--line);border-radius:18px;background:var(--panel)}.related a{display:inline-flex;gap:8px;align-items:center;margin:8px 8px 0 0;padding:8px 10px;border:1px solid var(--line);border-radius:999px;text-decoration:none;color:#dbeafe}.related span{color:var(--cyan);font-size:12px}.pager{display:flex;justify-content:space-between;gap:16px;margin-top:28px;padding-top:20px;border-top:1px solid var(--line)}.pager a{max-width:46%;padding:12px 14px;border:1px solid var(--line);border-radius:14px;background:var(--panel);text-decoration:none}.lightbox{position:fixed;inset:0;z-index:20;display:grid;place-items:center;background:rgba(0,0,0,.88);padding:24px}.lightbox[hidden]{display:none}.lightbox button{position:absolute;right:18px;top:18px;width:44px;height:44px;border:1px solid var(--line);border-radius:14px;background:#0f172a;color:#fff;font-size:28px;cursor:pointer}.lightbox img{max-width:96vw;max-height:92vh;border-radius:16px}.content-cards{margin:4px 0 22px}@media(max-width:1280px){.reader-layout{grid-template-columns:240px minmax(0,1fr)}.toc{display:none}}@media(max-width:900px){.app-shell{grid-template-columns:1fr}.sidebar{position:relative;height:auto}.content{padding:20px}.home-hero,.topic-hero{display:block;padding:22px}.reader-layout{grid-template-columns:1fr}.secondary-nav{position:relative;top:auto;max-height:420px}.home-hero h1,.topic-hero h1{font-size:42px}.category-head{display:block}.pager a{max-width:none}.pager{display:grid}}`, "utf8");
  fs.appendFileSync(path.join(outDir, "style.css"), `
.command-button{width:100%;display:flex;justify-content:space-between;align-items:center;margin:-6px 0 14px;padding:11px 12px;border:1px solid var(--line);border-radius:14px;background:rgba(15,23,42,.78);color:#dbeafe;cursor:pointer}.command-button:hover{border-color:rgba(34,211,238,.6);background:rgba(34,211,238,.08)}.command-button kbd{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:1px 5px}.side-level{border-top:1px solid var(--line);padding:12px 0}.side-level>summary{list-style:none;display:grid;gap:2px;cursor:pointer}.side-level>summary::-webkit-details-marker,.side-section>summary::-webkit-details-marker,.category-band>summary::-webkit-details-marker{display:none}.side-level>summary strong{display:inline-flex;width:max-content;padding:3px 8px;border:1px solid rgba(34,211,238,.5);border-radius:999px;color:#a5f3fc;font-size:12px}.side-level>summary span{font-weight:800;color:#f8fafc}.side-section{margin:9px 0 0 8px;border-left:1px solid var(--line);padding-left:9px}.side-section>summary{display:flex;justify-content:space-between;gap:8px;cursor:pointer;padding:7px 8px;border-radius:10px;color:#dbeafe;font-size:13px;font-weight:750}.side-section>summary:hover{background:rgba(34,211,238,.08)}.side-section>summary span{color:var(--cyan);font-size:11px}.level-band{margin:28px 0 34px;padding:22px;border:1px solid var(--line);border-radius:24px;background:rgba(2,6,23,.34)}.level-head{margin-bottom:18px}.level-head>span{display:inline-flex;margin-bottom:8px;padding:4px 10px;border:1px solid rgba(34,211,238,.55);border-radius:999px;color:#a5f3fc;font-size:12px;font-weight:900}.level-head h2{margin:0;font-size:clamp(28px,4vw,46px);line-height:1.05}.level-head p{max-width:860px;color:var(--muted);margin:10px 0 0}.category-band{padding:14px 0;border-top:1px solid var(--line)}.category-band>summary{display:flex;align-items:center;justify-content:space-between;cursor:pointer;margin-bottom:14px}.category-band>summary h3{margin:0;font-size:20px}.category-band>summary span{color:var(--cyan);font-size:13px}.command-palette{position:fixed;inset:0;z-index:30;background:rgba(0,0,0,.62);backdrop-filter:blur(12px);padding:9vh 18px}.command-palette[hidden]{display:none}.command-panel{max-width:760px;margin:0 auto;border:1px solid var(--line);border-radius:22px;background:#07111f;box-shadow:var(--shadow);overflow:hidden}.command-head{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid var(--line)}.command-head button{border:1px solid var(--line);border-radius:10px;background:#0f172a;color:#dbeafe;padding:6px 9px;cursor:pointer}.command-panel input{width:100%;border:0;border-bottom:1px solid var(--line);background:#020617;color:var(--text);font-size:18px;padding:16px;outline:0}.command-results{max-height:58vh;overflow:auto}.command-results a{display:block;padding:13px 16px;text-decoration:none;border-bottom:1px solid var(--line)}.command-results a:hover{background:rgba(34,211,238,.08)}.command-results small{color:var(--muted)}
`, "utf8");
}

function writeJs() {
  fs.writeFileSync(path.join(outDir, "script.js"), `const $=(s,r=document)=>r.querySelector(s);const $$=(s,r=document)=>[...r.querySelectorAll(s)];function prefix(){return location.pathname.includes('/pages/')?'../':''}function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}function initSearch(){const input=$('#globalSearch'),box=$('#searchResults');if(!input||!box||!window.SEARCH_INDEX)return;input.addEventListener('input',()=>{const q=input.value.trim().toLowerCase();if(!q){box.hidden=true;box.innerHTML='';return}const hits=window.SEARCH_INDEX.filter(x=>(x.title+' '+x.path+' '+x.tags.join(' ')+' '+x.mitre.join(' ')+' '+x.text).toLowerCase().includes(q)).slice(0,20);box.innerHTML=hits.map(h=>'<a href="'+prefix()+'pages/'+h.slug+'.html"><strong>'+esc(h.title)+'</strong><br><small>'+esc(h.path)+' · '+esc(h.level)+'</small></a>').join('')||'<a><small>No matches</small></a>';box.hidden=false})}function initCopy(){document.addEventListener('click',async e=>{const b=e.target.closest('.copy-code');if(!b)return;const code=b.closest('.code-shell')?.querySelector('code')?.innerText||'';try{await navigator.clipboard.writeText(code)}catch{const t=document.createElement('textarea');t.value=code;document.body.append(t);t.select();document.execCommand('copy');t.remove()}b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200)})}function initLightbox(){const lb=$('#lightbox');if(!lb)return;document.addEventListener('click',e=>{const b=e.target.closest('.image-button');if(!b)return;lb.hidden=false;$('img',lb).src=b.dataset.src;$('img',lb).alt=b.dataset.alt||''});lb.addEventListener('click',e=>{if(e.target===lb||e.target.tagName==='BUTTON')lb.hidden=true})}function highlight(){const words=/\\b(index|sourcetype|stats|table|where|eval|rex|timechart|Get-[A-Za-z]+|Set-[A-Za-z]+|net|reg|wevtutil|tasklist|wmic|curl|grep|findstr|SELECT|FROM|WHERE|AND|OR)\\b/g;$$('pre code').forEach(c=>{let t=esc(c.innerText);t=t.replace(/("[^"]*"|'[^']*')/g,'<span class="tok-str">$1</span>').replace(words,'<span class="tok-cmd">$1</span>').replace(/\\b(TA\\d{4}|T\\d{4}(?:\\.\\d{3})?|\\d{4})\\b/g,'<span class="tok-key">$1</span>');c.innerHTML=t})}initSearch();initCopy();initLightbox();highlight();`, "utf8");
}

function main() {
  cleanDir(outDir);
  ensureDir(pagesDir);
  ensureDir(jsonDir);
  ensureDir(pageJsonDir);
  ensureDir(imageDir);
  ensureDir(attachmentDir);

  const allFiles = walk(sourceDir);
  const mdFiles = allFiles.filter((file) => path.extname(file).toLowerCase() === ".md");
  const maps = copyAssets(allFiles);
  const pathToSlug = new Map();
  const slugCounts = new Map();
  for (const file of mdFiles) {
    const base = slugify(titleFromFile(file));
    const count = slugCounts.get(base) || 0;
    slugCounts.set(base, count + 1);
    pathToSlug.set(path.resolve(file), count ? `${base}-${hash(relFromSource(file))}` : base);
  }

  const nodes = mdFiles.map((file) => {
    const raw = readUtf8(file);
    const relPath = relFromSource(file);
    const noExt = relPath.replace(/\.md$/i, "").toLowerCase();
    const title = titleFromFile(file);
    const blocks = extractBlocks(raw);
    const links = parseMarkdownLinks(raw, file);
    const node = {
      id: noExt,
      file,
      relPath,
      title,
      slug: pathToSlug.get(path.resolve(file)),
      parentId: null,
      children: [],
      linkTargets: [],
      relatedLinks: [],
      raw,
      html: "",
      headings: blocks.headings,
      codeBlocks: blocks.codeBlocks,
      quotes: blocks.quotes,
      checklists: blocks.checklists,
      overview: firstParagraph(raw),
      level: classifyLevel(title, relPath, raw),
      tags: deriveTags(title, relPath, raw),
      mitre: [...new Set((`${title} ${relPath} ${raw}`.match(mitreRegex) || []).map((x) => x.toUpperCase()))].slice(0, 24),
      backlinks: []
    };
    node.linkTargets = links.filter((link) => link.isMarkdown && pathToSlug.has(path.resolve(link.local))).map((link) => relFromSource(path.resolve(link.local)).replace(/\.md$/i, "").toLowerCase());
    node.html = renderMarkdown(raw, file, maps, pathToSlug);
    node.study = buildStudy(node);
    return node;
  });

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const byPathNoExt = byId;
  const rootLinks = parseRootLinks();
  const rootOrder = new Map();
  rootLinks.forEach((link, index) => {
    const id = relFromSource(path.resolve(link.local)).replace(/\.md$/i, "").toLowerCase();
    rootOrder.set(id, index);
  });

  for (const node of nodes) {
    const parts = node.relPath.replace(/\.md$/i, "").split("/");
    for (let i = parts.length - 1; i > 0; i -= 1) {
      const candidate = parts.slice(0, i).join("/").toLowerCase();
      if (byPathNoExt.has(candidate)) {
        node.parentId = candidate;
        break;
      }
    }
  }

  for (const node of nodes) {
    if (node.parentId && byId.has(node.parentId)) byId.get(node.parentId).children.push(node.id);
  }

  for (const node of nodes) {
    const orderedLinkedChildren = node.linkTargets.filter((id) => byId.has(id) && byId.get(id).parentId === node.id);
    const folderOnly = node.children.filter((id) => !orderedLinkedChildren.includes(id));
    folderOnly.sort((a, b) => byId.get(a).title.localeCompare(byId.get(b).title));
    node.children = [...orderedLinkedChildren, ...folderOnly];
    node.relatedLinks = node.linkTargets.filter((id) => byId.has(id) && byId.get(id).parentId !== node.id && id !== node.id);
    for (const id of node.linkTargets) if (byId.has(id) && id !== node.id) byId.get(id).backlinks.push(node.id);
  }

  const directAssignments = new Map();
  const matchedCurriculum = curriculum.map((level) => ({
    ...level,
    sections: level.sections.map((section) => ({
      ...section,
      topics: section.topics.map((label) => {
        const node = findTopicByLabel(label, nodes);
        if (node) directAssignments.set(node.id, { level: level.level, levelId: level.id, sectionId: section.id, sectionTitle: section.title, label });
        return { label, node };
      })
    }))
  }));

  for (const level of matchedCurriculum) {
    for (const section of level.sections) {
      for (const item of section.topics) {
        if (!item.node) continue;
        const assignment = { level: level.level, levelId: level.id, sectionId: section.id, sectionTitle: section.title };
        for (const descendant of flattenTree(item.node, byId)) {
          const direct = directAssignments.get(descendant.id);
          if (!direct || descendant.id === item.node.id) {
            descendant.level = direct?.level || assignment.level;
            descendant.curriculumLevelId = direct?.levelId || assignment.levelId;
            descendant.curriculumSectionId = direct?.sectionId || assignment.sectionId;
            descendant.curriculumSectionTitle = direct?.sectionTitle || assignment.sectionTitle;
            descendant.study = buildStudy(descendant);
          }
        }
      }
    }
  }

  const summarize = (node) => node ? { title: node.title, slug: node.slug, level: node.level, children: node.children.length, id: node.id, overview: node.overview, relPath: node.relPath } : null;
  const nav = {
    levels: matchedCurriculum.map((level) => ({
      id: level.id,
      title: level.title,
      shortTitle: level.shortTitle,
      level: level.level,
      subtitle: level.subtitle,
      description: level.description,
      sections: level.sections.map((section) => ({
        id: section.id,
        title: section.title,
        topics: section.topics.map(({ label, node }) => ({ label, node: summarize(node) }))
      }))
    }))
  };

  const topLevelNodes = nodes.filter((node) => !node.parentId);

  const orderedRoots = [...topLevelNodes].sort((a, b) => (rootOrder.get(a.id) ?? 10000) - (rootOrder.get(b.id) ?? 10000) || a.title.localeCompare(b.title));
  const ordered = orderedRoots.flatMap((node) => flattenTree(node, byId));
  const navJson = {
    generatedAt: new Date().toISOString(),
    sourceRoot: path.basename(sourceRootMd),
    sourceFolder: path.basename(sourceDir),
    levels: nav.levels,
    tree: orderedRoots.map((node) => nodeToNav(node, byId))
  };

  fs.writeFileSync(path.join(jsonDir, "navigation.json"), JSON.stringify(navJson, null, 2), "utf8");
  fs.writeFileSync(path.join(jsonDir, "search-index.js"), `window.SEARCH_INDEX=${JSON.stringify(ordered.map((node) => ({
    title: node.title,
    slug: node.slug,
    level: node.level,
    path: [...ancestors(node, byId), node].map((n) => n.title).join(" / "),
    tags: node.tags,
    mitre: node.mitre,
    text: `${node.overview} ${node.headings.map((h) => h.text).join(" ")}`
  })))};`, "utf8");

  for (const node of nodes) {
    const pageJson = {
      id: node.id,
      title: node.title,
      slug: node.slug,
      relPath: node.relPath,
      level: node.level,
      curriculumLevelId: node.curriculumLevelId || null,
      curriculumSectionId: node.curriculumSectionId || null,
      curriculumSectionTitle: node.curriculumSectionTitle || null,
      tags: node.tags,
      mitre: node.mitre,
      parentId: node.parentId,
      children: node.children,
      relatedLinks: node.relatedLinks,
      backlinks: [...new Set(node.backlinks)],
      breadcrumbs: [...ancestors(node, byId), node].map((n) => ({ id: n.id, title: n.title, slug: n.slug })),
      headings: node.headings,
      overview: node.overview,
      study: node.study
    };
    fs.writeFileSync(path.join(pageJsonDir, `${node.slug}.json`), JSON.stringify(pageJson, null, 2), "utf8");
  }

  writeCss();
  writeJs();
  fs.appendFileSync(path.join(outDir, "script.js"), `\n(function(){function $(s,r=document){return r.querySelector(s)}function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}function prefix(){return location.pathname.includes('/pages/')?'../':''}function hay(x){return (x.title+' '+x.path+' '+x.level+' '+x.tags.join(' ')+' '+x.mitre.join(' ')+' '+x.text).toLowerCase()}function score(q,x){const h=hay(x);if(h.includes(q))return 1000-q.length;let i=0,n=0;for(const ch of h){if(ch===q[i]){n+=8;i++;if(i===q.length)break}else n-=.02}return i===q.length?n:-1}function find(q){q=q.trim().toLowerCase();if(!q)return(window.SEARCH_INDEX||[]).slice(0,12);return(window.SEARCH_INDEX||[]).map(x=>[score(q,x),x]).filter(([s])=>s>=0).sort((a,b)=>b[0]-a[0]).slice(0,30).map(([,x])=>x)}function html(list){return list.map(h=>'<a href=\"'+prefix()+'pages/'+h.slug+'.html\"><strong>'+esc(h.title)+'</strong><br><small>'+esc(h.path)+' · '+esc(h.level)+'</small></a>').join('')||'<a><small>No matches</small></a>'}const pal=$('#commandPalette'),open=$('#openCommand'),close=$('#closeCommand'),input=$('#commandInput'),results=$('#commandResults');if(!pal)return;function show(){pal.hidden=false;input.value='';results.innerHTML=html(find(''));setTimeout(()=>input.focus(),0)}function hide(){pal.hidden=true}open&&open.addEventListener('click',show);close&&close.addEventListener('click',hide);pal.addEventListener('click',e=>{if(e.target===pal)hide()});document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();show()}if(e.key==='Escape')hide()});input&&input.addEventListener('input',()=>{results.innerHTML=html(find(input.value))})})();\n`, "utf8");
  const stats = { pages: nodes.length, images: maps.imageMap.size, mitre: new Set(nodes.flatMap((node) => node.mitre)).size };
  fs.writeFileSync(path.join(outDir, "index.html"), renderIndex(nav, nodes, stats), "utf8");
  for (const node of nodes) fs.writeFileSync(path.join(pagesDir, `${node.slug}.html`), renderTopic(node, byId, nav, ordered), "utf8");
  console.log(`Generated ${nodes.length} hierarchical pages, ${maps.imageMap.size} images, ${maps.attachmentMap.size} attachments.`);
}

main();
