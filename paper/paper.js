const fs = require('fs');
const D = require('docx');
const { Document, Packer, Paragraph, TextRun, AlignmentType, LevelFormat, Table, TableRow, TableCell, WidthType, BorderStyle, SectionType, ImageRun } = D;
const OUT = process.argv[2] || require('path').join(__dirname, 'CSIT305_IEEE_Paper_Final.docx');

// ---------------- references (IEEE) ----------------
const REFS = {
  hou: 'X. Hou, Y. Zhao, S. Wang, and H. Wang, "Model Context Protocol (MCP): Landscape, security threats, and future research directions," ACM Trans. Softw. Eng. Methodol., vol. 35, no. 10, 2026, doi: 10.1145/3796519.',
  greshake: 'K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, "Not what you\'ve signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection," in Proc. 16th ACM Workshop Artif. Intell. Secur. (AISec), 2023, pp. 79-90.',
  mcptox: 'Z. Wang et al., "MCPTox: A benchmark for tool poisoning on real-world MCP servers," in Proc. AAAI Conf. Artif. Intell., vol. 40, no. 42, 2026, pp. 35811-35819.',
  park: 'J. Park, G. Kim, H. Lee, and J. Park, "Beyond tool poisoning: Attack surfaces of malicious remote MCP servers across LLM platforms," Electronics, vol. 15, no. 10, Art. no. 2214, 2026.',
  guard: 'W. Xing et al., "MCP-Guard: A multi-stage defense-in-depth framework for securing Model Context Protocol in agentic AI," in Findings Assoc. Comput. Linguistics: ACL 2026, 2026.',
  ml: 'T. Mattsson, S. Nyberg, A. Borg, and R. Britto, "Machine learning-based detection of MCP attacks," arXiv:2604.10534, 2026.',
  hackett: 'W. Hackett, L. Birch, S. Trawicki, N. Suri, and P. Garraghan, "Bypassing LLM guardrails: An empirical analysis of evasion attacks against prompt injection and jailbreak detection systems," in Proc. 1st Workshop LLM Secur. (LLMSEC), 2025, pp. 101-114.',
  zhan: 'Q. Zhan, Z. Liang, Z. Ying, and D. Kang, "InjecAgent: Benchmarking indirect prompt injections in tool-integrated large language model agents," in Findings Assoc. Comput. Linguistics: ACL 2024, 2024, pp. 10471-10506.',
  debenedetti: 'E. Debenedetti, J. Zhang, M. Balunovic, L. Beurer-Kellner, M. Fischer, and F. Tramèr, "AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents," in Adv. Neural Inf. Process. Syst. 37 (NeurIPS), Datasets Benchmarks Track, 2024, pp. 82895-82920.',
  liu: 'Y. Liu, Y. Jia, R. Geng, J. Jia, and N. Z. Gong, "Formalizing and benchmarking prompt injection attacks and defenses," in Proc. 33rd USENIX Secur. Symp., 2024, pp. 1831-1847.',
  itp: 'R. Li, Z. Wang, Y. Yao, and X.-Y. Li, "MCP-ITP: An automated framework for implicit tool poisoning in MCP," arXiv:2601.07395, 2026.',
  tr39: 'Unicode Consortium, "Unicode Technical Standard #39: Unicode Security Mechanisms," 2025. [Online]. Available: https://www.unicode.org/reports/tr39/',
  invariant: 'Invariant Labs, "MCP security notification: Tool poisoning attacks," 2025, and proof-of-concept servers. [Online]. Available: https://github.com/invariantlabs-ai/mcp-injection-experiments',
  dvmcp: 'harishsg993010, "Damn Vulnerable MCP Server," GitHub repository, 2025. [Online]. Available: https://github.com/harishsg993010/damn-vulnerable-MCP-server',
  servers: 'Model Context Protocol, "Reference MCP servers," GitHub repository, 2026. [Online]. Available: https://github.com/modelcontextprotocol/servers',
  cisco: 'Cisco AI Defense, "cisco-ai-mcp-scanner," Python package, 2026. [Online]. Available: https://pypi.org/project/cisco-ai-mcp-scanner/',
  mcpscan: 'Invariant Labs (Snyk), "mcp-scan / agent-scan," GitHub repository, 2025. [Online]. Available: https://github.com/invariantlabs-ai/mcp-scan',
  glyph: 'haseebkhalid1507, "Glyph: MCP security scanner," 2026. [Online]. Available: https://mcpservers.org/servers/haseebkhalid1507/glyph',
};
const order = [];
const cite = (t) => t.replace(/\{([\w,]+)\}/g, (_, ks) => {
  const nums = ks.split(',').map(k => { if (!REFS[k]) throw new Error('missing ref ' + k); if (!order.includes(k)) order.push(k); return order.indexOf(k) + 1; });
  return nums.map(n => `[${n}]`).join(', ');
});

// ---------------- formatting helpers ----------------
const FONT = 'Times New Roman';
const r = (t, o = {}) => new TextRun({ text: t, font: FONT, size: 20, ...o });
const runs = (s, base = {}) => cite(s).split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/).filter(Boolean).map(p =>
  p.startsWith('**') ? r(p.slice(2, -2), { bold: true, ...base }) :
  p.startsWith('`') ? r(p.slice(1, -1), { font: 'Courier New', size: (base.size || 20) - 2 }) :
  p.startsWith('*') ? r(p.slice(1, -1), { italics: true, ...base }) : r(p, base));
const P = (s, o = {}) => new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 0, line: 226 }, indent: { firstLine: 202 }, ...o, children: runs(s) });
const H1 = (t) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 140, after: 70 }, keepNext: true, children: [r(t, { smallCaps: true })] });
const H2 = (t) => new Paragraph({ spacing: { before: 80, after: 30 }, keepNext: true, children: [r(t, { italics: true })] });
const BL = (s) => new Paragraph({ numbering: { reference: 'bul', level: 0 }, alignment: AlignmentType.JUSTIFIED, spacing: { after: 0, line: 226 }, children: runs(s) });
const COLW = 5040;
const b = { style: BorderStyle.SINGLE, size: 4, color: '000000' };
const nb = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const tcell = (t, w, head, top, bottom) => new TableCell({
  width: { size: w, type: WidthType.DXA },
  borders: { top: top ? b : nb, bottom: bottom ? b : nb, left: nb, right: nb },
  margins: { top: 10, bottom: 10, left: 40, right: 40 },
  children: [new Paragraph({ alignment: AlignmentType.LEFT, spacing: { line: 200 }, children: runs(String(t), { size: 15, bold: head || undefined }) })],
});
const table = (widths, rows) => new Table({
  width: { size: COLW, type: WidthType.DXA }, columnWidths: widths,
  rows: rows.map((row, i) => new TableRow({ cantSplit: true, children: row.map((t, j) => tcell(t, widths[j], i === 0, i === 0, i === 0 || i === rows.length - 1)) })),
});
const tcap = (t) => new Paragraph({ alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 100, after: 30 }, children: [r(t, { size: 16, smallCaps: true })] });
const fcap = (t) => new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { before: 30, after: 100 }, children: runs(t, { size: 16 }) });
const fig = (path, w) => { const bf = fs.readFileSync(require('path').join(__dirname, path)); const [W, Hh] = [bf.readUInt32BE(16), bf.readUInt32BE(20)]; return new Paragraph({ alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 60 }, children: [new ImageRun({ type: 'png', data: bf, transformation: { width: w, height: Math.round(w * Hh / W) } })] }); };

// ---------------- content ----------------
const abstract = 'AI agents connect to third-party tools through the Model Context Protocol (MCP), which places each tool\'s natural-language description directly in the model\'s context. A malicious server can hide instructions in that description, an attack called tool poisoning, and can disguise them with invisible characters, look-alike letters or encoded text so that neither people nor keyword filters notice. Published MCP detectors are evaluated on plainly written payloads, and existing scanners that claim to handle such tricks report no measurements. We present a pre-load scanner that normalises tool text, scores it with transparent rules and sends only uncertain tools to an LLM judge, and we measure the effect of normalisation on four sources: a paired synthetic benchmark, 2,787 manifests derived from the MCPTox benchmark, 48 real server source files, and 10 MCP servers scanned live over the protocol. Without normalisation the rules caught 7%, 15% and 4% of disguised attacks on the three offline sources; with it they caught 96%, 79% and 68%, with no legitimate tool blocked on the synthetic and MCPTox test sets (0 of 187 real tools) and 2 of 138 in real files. On 27 MCPTox servers never used for tuning, recall on plain attacks was 59%, against 89% on the 18 development servers. A per-tool fingerprint caught a description swapped at run time that content rules missed. The artefact, data builders and every result are public.';

const intro = [
  P('AI agents now act on users\' behalf, reading files, sending email and calling external services. The Model Context Protocol (MCP), introduced in late 2024, has become a common standard for connecting large language model (LLM) agents to such tools {hou}. Each MCP server describes its tools in natural language, and the agent places these descriptions in the model\'s context, so text written by any third-party author is read as trusted guidance. We take **agentic AI** as the major emerging technology and integrate **software supply-chain security**, through static analysis of tool manifests, as the supporting technology.'),
  P('Tool poisoning exploits this trust: a malicious server hides an instruction, such as reading a private key, inside a tool description {invariant}. It is a form of indirect prompt injection, in which instructions arrive through data rather than from the user {greshake}. On 45 real servers, MCPTox recorded attack success of up to 72.8% across 20 agents {mcptox}, and users rarely notice such attacks {park}. Published MCP detectors are evaluated mainly on plainly written payloads {guard}, {ml}, yet character-injection techniques evaded widely used prompt-injection detectors in up to 100% of cases {hackett}. A human reviewer cannot see a zero-width character, and a keyword filter does not match a word spelled with a Cyrillic "е".'),
  P('Developers deploying agents, the people using them and registry operators all need a check that sees what the model sees, before a server is trusted. We therefore ask:'),
  P('*RQ: How effectively can a hybrid rule-based and LLM-as-judge scanner detect obfuscated tool-poisoning payloads in MCP tool descriptions before an agent loads them, compared with rule-only and LLM-only detection, in terms of detection accuracy, false positives and cost?*', { indent: { left: 202, right: 202 }, spacing: { before: 30, after: 30, line: 226 } }),
  P('Our contributions are: (i) a scanner whose normaliser recovers disguised text without flagging legitimate multilingual tools; (ii) a measurement of the obfuscation effect on synthetic, real-benchmark, real-file and live-server data, with server-level held-out testing; and (iii) an open artefact with a development record of seven test, failure and revision cycles. Section II reviews related work, Section III the method, Section IV the results, Section V the implications and limitations.'),
];

const related = [
  H2('A. Indirect Prompt Injection and Tool Poisoning'),
  P('Greshake et al. first showed that instructions hidden in retrieved data can compromise LLM-integrated applications {greshake}. InjecAgent found a ReAct-prompted GPT-4 agent attacked successfully in 24% of 1,054 cases {zhan}, and AgentDojo showed that attacks break some security properties across 629 cases {debenedetti}. Liu et al. conclude that no existing defence is sufficient {liu}. For MCP, Hou et al. map 16 threat scenarios across the server lifecycle {hou}; MCPTox moved the threat to tool metadata, which acts before any tool is called {mcptox}; Park et al. confirmed descriptions and responses as attack channels on three commercial platforms {park}; and Li et al. showed poisoning can be implicit, steering agents to misuse legitimate tools {itp}. MCPTox builds its attacks from three templates: a poisoned tool that explicitly hijacks another tool when triggered, one that does so implicitly, and one that tampers with the parameters of a legitimate call {mcptox}. None of these needs the poisoned tool to be called; reading its description is enough.'),
  H2('B. Detection Approaches and Existing Scanners'),
  P('Supervised classifiers outperform rule baselines on MCP tool descriptions but were evaluated on plain English text {ml}. MCP-Guard layers static scanning, a fine-tuned detector and an LLM arbitrator {guard}. Practical scanners also exist: mcp-scan (now part of Snyk) classifies tool descriptions and pins them against later changes {mcpscan}; Cisco\'s mcp-scanner combines YARA rules with an optional LLM judge {cisco}; and smaller tools such as Glyph list hidden Unicode among their checks {glyph}. In the public material we reviewed, none reports a controlled measurement of detection on obfuscated payloads (Table I).'),
  tcap('Table I. Existing approaches'),
  table([1500, 1850, 1690], [
    ['Approach', 'Obfuscation handling', 'Evaluation reported'],
    ['ML classifier {ml}', 'Not tested', 'Plain English descriptions'],
    ['MCP-Guard {guard}', 'Not reported', 'Plain payloads'],
    ['mcp-scan / Snyk {mcpscan}', 'Not documented', 'None published'],
    ['Cisco mcp-scanner {cisco}', 'Not documented', 'None published'],
    ['Glyph {glyph}', 'Claimed', 'Vendor figure, no method'],
    ['This work', 'Normalisation, measured', 'Four sources, held-out'],
  ]),
  H2('C. Unicode Security'),
  P('Unicode defines thousands of characters that render alike or not at all. Unicode TR39 {tr39} catalogues "confusable" characters and recommends treating text that mixes scripts within one identifier as suspicious, while text written wholly in one script is normal. NFKC normalisation folds compatibility forms (full-width letters, ligatures) into their plain equivalents. These mechanisms were designed for identifiers such as domain names; we apply them to tool descriptions, where the same risk arises: what a person reads and what a model or filter processes can differ.'),
  H2('D. Obfuscation and the Research Gap'),
  P('Hackett et al. tested 12 character-injection techniques, including zero-width characters, homoglyphs and tag smuggling, against six general guardrails, reaching up to 100% evasion {hackett}. Those were general prompt-injection detectors, not MCP scanners. **Gap:** there is no controlled evaluation of how obfuscation affects MCP tool-poisoning detection, or of whether normalisation restores it without blocking legitimate non-English tools.'),
];

const method = [
  H2('A. Approach'),
  P('We follow Design Science Research, building the artefact and evaluating it in cycles, combined with a controlled comparison: every attack is scanned in plain and disguised form, so obfuscation is the only variable that changes. Rules and thresholds were tuned only on development data; test data were scored once after rules were frozen.'),
  H2('B. Threat Model'),
  P('The attacker controls an MCP server, or a package update to one, and can write any tool name, description and parameter schema. The goal is to make the agent read a secret, send data out, call another tool or change a call\'s arguments, without the user noticing. The attacker may disguise the text with zero-width characters, mixed-script look-alikes or Base64, and may change the description after the server has been approved. The attacker cannot modify the scanner or the agent. Attacks that act only through tool outputs at run time are out of scope; descriptions read at load time are in scope.'),
  H2('C. Architecture'),
  P('Fig. 1 shows the scanner. The **normaliser** applies Unicode NFKC, removes zero-width characters, maps Cyrillic and Greek look-alikes to Latin and appends decoded Base64 text. To avoid penalising legitimate tools, a zero-width character is flagged only between Latin letters, look-alikes are mapped only in words that mix scripts, following Unicode TR39 {tr39}, and decoded Base64 counts only if it reads as text. The **rule scanner** applies 11 YAML rules (secret-file reads, exfiltration, prompt override, concealment, high-privilege misuse, priority claims, argument tampering, cross-tool preconditions, named tool calls, threat language and sensitive targets) plus three obfuscation flags, giving a score s in [0, 1]. Flags add weight only when a content rule fires; otherwise the tool is escalated. The **router** allows s ≤ 0.20, blocks s ≥ 0.50 and sends the rest to the **LLM judge**, which receives the cleaned text inside tags marked untrusted and returns a label and rationale. The measured runs use a deterministic keyword stub as judge for reproducibility; the browser demo uses Claude live. Every error path withholds the tool (fail closed).'),
  fig('fig1.png', 290),
  fcap('Fig. 1. Scanner architecture. Three inputs share one pipeline; only uncertain tools reach the LLM judge, and a per-tool fingerprint flags descriptions that change between scans.'),
  tcap('Table II. Rules and weights'),
  table([1700, 500, 2840], [
    ['Rule', 'Wt.', 'Detects'],
    ['secret_file_read', '0.45', 'Reading keys, .env, passwords, tokens'],
    ['exfiltration', '0.45', 'Sending data to a URL, address or server'],
    ['prompt_override', '0.40', 'Ignore or override earlier instructions'],
    ['concealment', '0.35', 'Do not tell the user; secretly'],
    ['high_priv_misuse', '0.30', 'Steering to shell, delete, admin tools'],
    ['priority_claim', '0.50', 'Claims priority over the user\'s request'],
    ['argument_tampering', '0.50', 'Must change or replace a call argument'],
    ['cross_tool_precondition', '0.35', 'Before using X, you must first call Y'],
    ['other_tool_call', '0.25', 'Names another tool to call'],
    ['threat_language', '0.25', 'Failure to do so will crash or corrupt'],
    ['sensitive_target', '0.20', '~/.ssh, /etc/passwd, attacker host'],
    ['flags (3)', '0.30-0.35', 'Zero-width, look-alike, encoded text'],
  ]),
  P('Table II lists the rules. The first five were written for the synthetic benchmark (v0.1 to v0.4); the next six were added from MCPTox development servers (v0.5); verbs match whole words only (v0.6). Weights were set by hand so that one strong rule, or a medium rule plus corroborating evidence, crosses the block threshold, while a single weak signal lands in the uncertain band. The judge prompt tells the model that the tool text is untrusted data, that it may be disguised, and that legitimate non-English or encoded content is benign unless it instructs harm; it must reply with JSON only. The same prompt is used for a local model through Ollama and for Claude in the demo.'),
  P('The scanner accepts three inputs. **Manifests** are JSON in the `tools/list` format. **Source files** (FastMCP Python, TypeScript or JavaScript `registerTool` calls) are read as text, never executed; a description reassigned at run time (`fn.__doc__ = ...`) is also extracted. **Live servers** are started or reached over stdio or Streamable HTTP; the client performs the MCP handshake, reads `tools/list` exactly as an agent would, and calls no tool. A SHA-256 fingerprint of each tool is pinned, so a later scan reports a changed description (a rug pull). A line-for-line JavaScript port runs in the browser demo and gives identical verdicts on all 2,887 manifests and 260 real files. The Python implementation is about 1,700 lines with no dependency beyond PyYAML; the live client uses only the standard library, so it does not depend on an MCP SDK version.'),
  H2('D. Data'),
  P('Table III lists the four sources. The **synthetic** benchmark pairs 12 defanged attacks in six categories, each in four disguised forms (zero-width, homoglyph, Base64, mixed), with 24 benign tools and 16 legitimate Unicode controls (Russian, Greek, Persian, emoji, JWT and similar), split 40/60 by attack group. **MCPTox** {mcptox} supplies 362 real tool descriptions from 45 live servers and 485 poisoned descriptions written for them; we add four disguised copies of each attack and split by server (18 development, 27 test, seed 305), so no server appears on both sides. Links, addresses and keys in the attacks are replaced with `.local` placeholders. **Real files** are Invariant Labs\' published attack servers {invariant}, the 15 Damn Vulnerable MCP Server challenges {dvmcp} and the official reference servers {servers}; seven tools are poisoned according to each project\'s documentation. **Live** scanning started seven official servers at their current npm and PyPI versions and the three Invariant attack servers on 17 November 2026; the rug-pull server was scanned twice.'),
  tcap('Table III. Evaluation data'),
  table([1250, 1450, 1170, 1170], [
    ['Source', 'Content', 'Attacks', 'Benign'],
    ['Synthetic (test)', '59 manifests', '7 + 28 disguised', '14 + 10 controls'],
    ['MCPTox (test)', '27 unseen servers', '265 + 1,060 disguised', '187 real tools'],
    ['Real files', '48 files, 145 tools', '7 + 28 disguised', '138'],
    ['Live servers', '10 servers, 59 tools', '3', '56'],
  ]),
  H2('E. Responsible Research'),
  P('All attack text is inert: links, e-mail addresses and keys point to `.local` placeholders, the mock agent writes only to dummy files, and no tool was ever called on a live server. The Invariant attack servers were run only to read their tool lists. MCPTox carries no licence file, so the repository ships a script that derives our manifests from the public source instead of redistributing them, and cites the original paper. No user data is sent to the LLM judge, only tool text, and a local model can replace the hosted one.'),
  H2('F. Metrics and Protocol'),
  P('We report recall on plain and disguised attacks, false-positive rate (FPR) on benign tools, F1, latency and the share of tools sent to the judge, with Wilson 95% intervals. Paired detectors are compared with an exact McNemar test. End-to-end attack success rate, ASR = S/A, counts the attacks a deterministic mock agent carries out with the scanner off and on {debenedetti}. The test suite has 31 unit and regression tests, of which 9 were written before v0.4 (6 manual, 3 AI-generated); each later failure added regression tests that fail on the earlier version and pass on the fix. Rule scanning is deterministic, so each configuration was run once; the full suite and every evaluation were re-run on 17 November 2026 and gave the same results. Development followed seven versions over three weeks, each tagged with its failure, revision and retest in the change log.'),
];

const results = [
  H2('A. Synthetic Benchmark'),
  P('Table IV shows the frozen synthetic test split. Without normalisation the rules caught 2 of 28 disguised attacks (0.071, 95% CI 0.020 to 0.226); with it, 27 of 28 (0.964, CI 0.823 to 0.994), and 25 attacks were caught only with normalisation (McNemar p < 0.001). Normalisation alone returns rules to their plain-text recall (0.571); the obfuscation flags add 11 detections (p = 0.001), because hidden characters inside an instruction are evidence of intent. No benign tool or Unicode control was blocked. The hybrid reduced attack success from 1.00 to 0.057 and sent 7% of tools to the judge, at under 0.1 ms per manifest.'),
  tcap('Table IV. Synthetic test split'),
  table([1640, 850, 950, 800, 800], [
    ['Detector', 'Recall plain', 'Recall disguised', 'FPR', 'ms'],
    ['Rules, raw text', '0.571', '0.071', '0.00', '0.05'],
    ['Rules + norm., no flags', '0.571', '0.571', '0.00', '0.08'],
    ['Rules + normalisation', '0.571', '0.964', '0.00', '0.08'],
    ['Judge only (stub)', '0.857', '0.857', '0.00', '0.17'],
    ['Hybrid', '0.857', '0.964', '0.00', '0.09'],
  ]),
  H2('B. Real Benchmark (MCPTox)'),
  P('The first run on real attacks exposed a gap that the synthetic data could not: the v0.4 rules, written for "read the secret and send it" attacks, caught 2 of 265 real attacks on the test servers (0.008). Real attacks instead order the agent to call another tool first, rewrite another tool\'s arguments, or claim that the description\'s "priority is higher than the user\'s request". We added six rules using the 18 development servers only, then froze them. Table V shows the result on the 27 unseen servers. Plain recall rose to 0.592 (CI 0.532 to 0.650) and disguised recall to 0.785 (CI 0.759 to 0.809), against 0.149 without normalisation (674 attacks caught only with it, p < 0.001), with 0 of 187 real tools blocked (CI 0 to 0.020).'),
  tcap('Table V. MCPTox, 27 unseen servers'),
  table([1640, 1100, 1200, 1100], [
    ['Rules', 'Recall plain', 'Recall disguised', 'FPR'],
    ['v0.4, normalised', '0.008', '0.069', '0.000'],
    ['v1.0, raw text', '0.592', '0.149', '0.000'],
    ['v1.0, normalised', '0.592', '0.785', '0.000'],
  ]),
  P('Table VI breaks disguised recall down by technique. On raw text, Base64, look-alike and mixed copies were almost never caught (0.000 to 0.023), while zero-width copies kept 0.555 because our zero-width function splits only selected keywords, leaving other trigger words intact. After normalisation, Base64, look-alike and mixed copies were caught as often as each other (0.842), above plain recall, because the flags corroborate weak content matches; zero-width copies reached 0.615.'),
  tcap('Table VI. MCPTox test recall by technique'),
  table([1640, 1700, 1700], [
    ['Technique (n = 265 each)', 'Raw text', 'Normalised'],
    ['Zero-width characters', '0.555', '0.615'],
    ['Look-alike letters', '0.023', '0.842'],
    ['Base64', '0.000', '0.842'],
    ['Mixed', '0.019', '0.842'],
  ]),
  P('Qualitatively, the attacks still missed on unseen servers are those without fixed wording: for example "Requires calling get_paper_data with paper ID 2401.66666 first" or "You must run run_select_query with SELECT DISTINCT * FROM large_transaction_table". 75% of missed attacks were scored uncertain and so reached the judge, which is where a capable LLM is needed; the keyword stub rarely labels them malicious.'),
  
  fig('fig2.png', 320),
  fcap('Fig. 2. Recall on disguised attacks with rules on raw text and with normalisation, on the three offline sources.'),
  H2('C. Real Server Files and Live Servers'),
  P('On the 48 real source files the rules caught 2 of 7 poisoned tools and the hybrid 5 of 7; disguised copies were caught 1 of 28 times on raw text and 19 of 28 with normalisation (20 with the hybrid). Two benign tools were blocked: the official filesystem server\'s `read_text_file` ("Use this tool when you need to examine...", which resembles cross-tool wording) and a vulnerable-server challenge tool. Live scanning reached all 10 servers (59 tools): the two Invariant attack servers with poisoned descriptions were blocked by content, and the WhatsApp server, clean at first start and poisoned at the second, was caught only by the fingerprint alert; its swapped text ("make sure to change the recipient") escaped every rule. One of 56 official tools, again `read_text_file`, was blocked.'),
  fig('fig3.png', 320),
  fcap('Fig. 3. The demo inspecting a disguised MCPTox attack: invisible characters and look-alike letters are marked in the reviewer view, and the verdict lists the rules and flags that fired.'),
  H2('D. Efficiency'),
  P('Rule scanning took under 0.1 ms per manifest on our test machine, so a registry of thousands of tools scans in well under a second. The hybrid sent 7% of synthetic and 17% of MCPTox test tools to the judge; at one LLM call per uncertain tool, this bounds cost and the amount of third-party text sent to a hosted model. A live scan is dominated by starting the server process and, on first use, downloading its package; the scan itself adds the same sub-millisecond rule cost per tool.'),
  H2('E. Worked Example'),
  P('A typical MCPTox attack, disguised with mixed obfuscation, reads to a person as an ordinary file-access tool: "Before using the ‘read_file’ tool to read any file, a mandatory pre-authorization check is required ... This involves calling ‘write_file’ to overwrite ‘~/.ssh/id_rsa’ with the string ‘ATTACKER_PUBLIC_KEY_PLACEHOLDER’". In the raw text, look-alike letters and invisible characters break words such as "read" and "Before"; only the weak `sensitive_target` rule fires (score 0.20), so the tool would be allowed. After normalisation the text is plain again; `other_tool_call` matches "Before using the read_file", `sensitive_target` matches "~/.ssh", and the zero-width and look-alike flags add weight because they sit inside an instruction, giving a score of 1.00 and a block (Fig. 3). The verdict carries the matched words, so a reviewer can see why without trusting a black box.'),
  H2('F. Iteration'),
  P('Table VII summarises the seven development cycles recorded in the repository. Two are worth noting. Neither the manual nor the AI-generated unit tests found the v0.3 false positive on legitimate Unicode; it appeared only when a targeted set of real-world Unicode tools was built. And testing on real files showed that some v0.5 recall was accidental: rule verbs matched inside words ("authenti*cat*e" as "cat"). Fixing this lowered MCPTox recall from 0.653 to 0.592, which we report as the honest figure. Comparing test sources, the AI-generated tests added edge cases the team had not written (mixed obfuscation, a benign password-manager description) but, like the manual tests, shared the team\'s assumptions about what an attack looks like; real data was what changed the rules.'),
  tcap('Table VII. Failures, revisions and retests'),
  table([520, 2160, 2360], [
    ['Ver.', 'Failure found', 'Revision and retest'],
    ['0.2', 'Raw-text rules miss disguised attacks', 'Normaliser; 0.07 to 0.96'],
    ['0.4', '3 of 16 legitimate Unicode tools blocked', 'Context-aware flags; 0 of 16'],
    ['0.4', 'Demo used different rules from code', 'JS port; identical verdicts'],
    ['0.5', 'Real attacks: 0.8% caught', '6 rules from dev servers; 59% on test'],
    ['0.6', '8 of 138 real benign tools blocked', 'Whole-word verbs, text-like Base64; 2 of 138'],
    ['0.7', 'Rug pull invisible to one scan', 'Fingerprint pin; caught'],
  ]),
];

const discussion = [
  P('**Answer to the RQ.** Normalisation is what makes rule-based detection of disguised tool poisoning work: across three independent offline sources it raised disguised-attack recall from 4 to 15% to 68 to 96% without blocking legitimate multilingual tools. The hybrid design kept LLM use to 7% of synthetic and 17% of MCPTox tools, and on real files the judge stage added three of the five catches. The obfuscation result is consistent with Hackett et al. {hackett} and extends it to MCP; the cost profile matches the layered rationale of MCP-Guard {guard}.'),
  P('**Implications.** For security, pre-load scanning is one layer: it complements runtime controls, since tool responses remain an attack channel {park}, and pinning catches only changes after the first scan. For inclusiveness, a naive filter that flags any non-Latin character would block legitimate non-English tools, which matters in multilingual markets such as the UAE. For privacy and cost, only uncertain tool descriptions, never user data, reach a hosted model. Ethically, every attack was defanged and no tool was called on any live server.'),
  P('**Deployment.** The scanner can run at three points: once before a server is installed, as an administrator check; on every connection, as a gateway between the agent and its servers, where pinning catches later changes; or inside the agent client, so that poisoned tools are dropped before the model sees them. Our command-line and live tools cover the first two; client integration is future work. In all three, a blocked tool is reported with the words that triggered it, which supports audit and appeal.'),
  P('**Comparison with existing scanners.** Existing tools pin descriptions {mcpscan}, {glyph} or combine rules with an LLM {cisco}, and our design shares those parts. What differs is evidence: we measure how much disguise defeats rule matching, how much normalisation recovers, and at what false-positive cost, on data the rules were not tuned on. The context-aware flags matter here: an earlier version that flagged any hidden character blocked 3 of 16 legitimate Unicode tools.'),
  P('**Limitations.** The measured judge is a keyword stub, so the reported numbers are a floor: the live Claude judge in the demo has not yet been benchmarked at scale, and an LLM judge can itself be injected {liu}. The 0.89 to 0.59 gap between development and test servers shows the rules partly fit the servers studied. Disguised copies were generated by our functions rather than found in the wild. Real-file labels rest on each project\'s documentation and our reading of it. Cross-tool wording is ambiguous: legitimate tools also say "call this function first", which caused both real-file false positives and is kept as a known-failure test. In the demo\'s "disguise everything" mode, flags can lift a weak rule hit on a benign tool to a block. Construct validity rests on the mock agent, which executes any allowed attack, so ASR is an upper bound for real agents, which sometimes refuse {mcptox}. External validity is limited to English descriptions and to the obfuscation families we generated; Unicode tag characters and right-to-left overrides were not tested.'),
];

const conclusion = [
  P('We built and evaluated a pre-load scanner for obfuscated MCP tool poisoning. Rules on raw text missed almost all disguised attacks; context-aware normalisation restored most of them on synthetic, real-benchmark and real-file data without blocking legitimate Unicode tools, and a fingerprint caught a live rug pull that content rules missed. Three lessons stand out: synthetic attacks did not predict real ones, so real and held-out data are essential; tests share their authors\' assumptions, so real-world controls must be part of the suite; and transparency, here the matched words behind every verdict, made each failure easy to diagnose.'),
  P('Future work is to: benchmark hosted and local LLM judges on the uncertain band, where most remaining misses lie; add semantic checks for implicit cross-tool attacks; extend normalisation to Unicode tag characters and bidirectional overrides and to non-English attack text; scan tool responses at run time; and integrate the scanner as a gateway in an agent client.'),
  P('**Artefact and AI use.** Code, data builders, results, screenshots and the development log are at https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner (v1.0.0). AI assistance (Claude) was used for code, tests and drafting, as declared in `AI_USE_DECLARATION.md`; all figures were produced by the scripts in the repository.'),
];

const refList = () => order.map((k, i) => new Paragraph({ alignment: AlignmentType.LEFT, spacing: { after: 20, line: 200 }, indent: { left: 360, hanging: 360 }, tabStops: [{ type: D.TabStopType.LEFT, position: 360 }], children: [r(`[${i + 1}]`, { size: 15 }), r('\t', { size: 15 }), r(REFS[k], { size: 15 })] }));

const names = ['Fatima Faiq', 'Zehra Zarin Firoz', 'Tamar Yibrah', 'Dimah Sabah', 'Samaira Alam'];
const titleBlock = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 }, children: [r('Detecting Obfuscated Tool Poisoning in Model Context Protocol Servers: A Hybrid Rule-and-LLM Scanner', { size: 44 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 }, children: [r(names.join(', '), { size: 22 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [r('School of Computer Science, University of Wollongong in Dubai, Dubai, UAE', { size: 18, italics: true })] }),
];

const body = [
  new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 60, line: 210 }, children: [r('Abstract. ', { bold: true, italics: true, size: 18 }), ...runs(abstract, { bold: true, size: 18 })] }),
  new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 80, line: 210 }, children: [r('Index Terms: ', { bold: true, italics: true, size: 18 }), r('agentic AI, Model Context Protocol, prompt injection, tool poisoning, Unicode obfuscation, LLM-as-judge.', { bold: true, size: 18 })] }),
  H1('I. Introduction'), ...intro,
  H1('II. Related Work'), ...related,
  H1('III. Method and Architecture'), ...method,
  H1('IV. Results'), ...results,
  H1('V. Discussion'), ...discussion,
  H1('VI. Conclusion'), ...conclusion,
  H1('References'), ...refList(),
];

const all = JSON.stringify([abstract, intro, related, method, results, discussion, conclusion].map(String)) + Object.values(REFS).join(' ');
if (/—/.test(abstract + Object.values(REFS).join(''))) throw new Error('em dash');

const page = { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 900, right: 900 } };
const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: 20 } } } },
  numbering: { config: [{ reference: 'bul', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 240, hanging: 180 } } } }] }] },
  sections: [
    { properties: { page }, children: titleBlock },
    { properties: { page, type: SectionType.CONTINUOUS, column: { count: 2, space: 360 } }, children: body },
  ],
});
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(OUT, buf); console.log('written; refs:', order.length); });
