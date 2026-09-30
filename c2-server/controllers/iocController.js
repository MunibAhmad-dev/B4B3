"use strict";

const path = require("path");

function extractIOCs(bot) {
  const sets = {
    files: new Set(), ips: new Set(), registry: new Set(),
    processes: new Set(), services: new Set(), ports: new Set(), extensions: new Set(),
  };

  for (const evt of (bot.events || [])) {
    if (evt.path)   sets.files.add(evt.path);
    if (evt.remote) {
      const [ip, port] = evt.remote.split(":");
      if (ip)   sets.ips.add(ip);
      if (port) sets.ports.add(Number(port));
    }
    if (evt.hive && evt.value) sets.registry.add(`${evt.hive}\\${evt.value}`);
    else if (evt.hive)         sets.registry.add(evt.hive);
    if (evt.name && evt.cat === "process") sets.processes.add(evt.name);
    if (evt.service) sets.services.add(evt.service);
  }
  for (const f of (bot.files || [])) {
    const ext = (f.match(/\.[^.]+$/) || [""])[0].toLowerCase();
    if (ext) sets.extensions.add(ext);
  }
  for (const e of (bot.netlog || [])) {
    if (e.srcIp && e.srcIp !== "unknown" && e.srcIp !== "::1" && e.srcIp !== "127.0.0.1")
      sets.ips.add(e.srcIp);
  }

  return {
    generated:  new Date().toISOString(),
    bot:        bot.id,
    files:      [...sets.files],
    ips:        [...sets.ips],
    registry:   [...sets.registry],
    processes:  [...sets.processes],
    services:   [...sets.services],
    ports:      [...sets.ports],
    extensions: [...sets.extensions],
  };
}

function iocsToCSV(iocs) {
  const rows = [["type", "value"]];
  const add = (t, arr) => arr.forEach(v => rows.push([t, String(v).replace(/"/g, '""')]));
  add("file", iocs.files); add("ip", iocs.ips); add("registry", iocs.registry);
  add("process", iocs.processes); add("service", iocs.services);
  add("port", iocs.ports); add("extension", iocs.extensions);
  return rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
}

function iocsToSTIX(bot, iocs) {
  const uid = () => "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
  });
  const now = new Date().toISOString();
  const objects = [{
    type: "identity", spec_version: "2.1", id: `identity--${uid()}`,
    created: now, modified: now, name: "B4B3-RAT C2 Server", identity_class: "system",
  }];
  const push = (name, pattern) => objects.push({
    type: "indicator", spec_version: "2.1", id: `indicator--${uid()}`,
    created: now, modified: now, name, pattern, pattern_type: "stix", valid_from: now,
    labels: ["malicious-activity"], confidence: 80,
  });
  iocs.files.forEach(f    => push(`Suspicious file: ${f}`,    `[file:name = '${path.basename(f)}']`));
  iocs.ips.forEach(ip     => push(`C2 IP: ${ip}`,             `[ipv4-addr:value = '${ip}']`));
  iocs.registry.forEach(r => push(`Registry key: ${r}`,       `[windows-registry-key:key = '${r}']`));
  iocs.processes.forEach(p=> push(`Suspicious process: ${p}`, `[process:name = '${p}']`));
  iocs.ports.forEach(p    => push(`C2 port: ${p}`,            `[network-traffic:dst_port = ${p}]`));
  return { type: "bundle", id: `bundle--${uid()}`, spec_version: "2.1", objects };
}

function iocsToMarkdown(bot, iocs) {
  const rs        = bot.riskBreakdown || [];
  const score     = bot.riskScore || 0;
  const riskLevel = score >= 100 ? "CRITICAL" : score >= 65 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  const techniques = [...new Set((bot.events||[]).filter(e=>e.tid).map(e=>`${e.tid} — ${e.tname||""}`))];
  const incidents  = (bot.incidents||[]).filter(i => i.status === "open");

  return `# Incident Report — Bot ${bot.id}

**Generated:** ${new Date().toLocaleString()}
**Risk Level:** ${riskLevel} (${score} pts)
**First Seen:** ${bot.firstSeen}
**Last Seen:**  ${bot.lastSeen}
**Events:**     ${(bot.events||[]).length}
**Incidents:**  ${incidents.length} open

---

## Risk Breakdown

| ID | Finding | Evidence | Score |
|---|---|---|---|
${rs.map(r=>`| ${r.id} | **${r.name}** | ${r.desc} | +${r.score} |`).join("\n")||"| — | No risk factors triggered | — | 0 |"}

**Total: ${score} / 200**

---

## MITRE ATT&CK Techniques

${techniques.length ? techniques.map(t => `- \`${t}\``).join("\n") : "_No mapped techniques._"}

---

## Open Incidents

${incidents.length ? incidents.map(i =>
  `### ${i.name} (${i.confidence}% confidence)\n**Severity:** ${i.severity}  \n**Created:** ${i.created}  \n${i.description}`
).join("\n\n") : "_No open incidents._"}

---

## IOCs

### Files
${iocs.files.map(f=>`- \`${f}\``).join("\n")||"_None._"}

### IP Addresses
${iocs.ips.map(i=>`- \`${i}\``).join("\n")||"_None._"}

### Registry Keys
${iocs.registry.map(r=>`- \`${r}\``).join("\n")||"_None._"}

### Processes
${iocs.processes.map(p=>`- \`${p}\``).join("\n")||"_None._"}

### Ports
${iocs.ports.map(p=>`- \`${p}\``).join("\n")||"_None._"}

### Extensions
${iocs.extensions.map(e=>`- \`${e}\``).join("\n")||"_None._"}
`;
}

module.exports = { extractIOCs, iocsToCSV, iocsToSTIX, iocsToMarkdown };
