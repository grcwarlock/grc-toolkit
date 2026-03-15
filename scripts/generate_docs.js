const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, HeadingLevel,
  BorderStyle, WidthType, ShadingType, PageNumber, PageBreak,
  TableOfContents, TabStopType, TabStopPosition,
} = require("docx");

// ── Design System ──
const PAGE_W = 12240;
const MARGIN = 1440;
const CW = PAGE_W - 2 * MARGIN;

// Color palette — warm navy + teal accent
const C = {
  navy:     "1A2744",
  navyMed:  "2C3E5A",
  teal:     "0EA5A0",
  tealLight:"E0F5F4",
  tealPale: "F0FAF9",
  slate:    "475569",
  slateL:   "94A3B8",
  grayBg:   "F8FAFC",
  grayLine: "E2E8F0",
  grayText: "64748B",
  white:    "FFFFFF",
  black:    "1E293B",
  green:    "059669",
  amber:    "D97706",
  red:      "DC2626",
  codeBg:   "F1F5F9",
};

const noBorder = { style: BorderStyle.NONE, size: 0 };
const noBorders = { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder };
const thinBorder = { style: BorderStyle.SINGLE, size: 1, color: C.grayLine };
const thinBorders = { top: thinBorder, bottom: thinBorder, left: thinBorder, right: thinBorder };
const pad = { top: 80, bottom: 80, left: 120, right: 120 };

// ── Helper Functions ──

function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] });
}
function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] });
}
function h3(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(text)] });
}

function p(text) {
  return new Paragraph({
    spacing: { after: 160, line: 300 },
    children: [new TextRun({ text, font: "Calibri", size: 22, color: C.slate })],
  });
}

function pRich(runs) {
  return new Paragraph({
    spacing: { after: 160, line: 300 },
    children: runs.map(r => {
      if (typeof r === "string") return new TextRun({ text: r, font: "Calibri", size: 22, color: C.slate });
      return new TextRun({ font: "Calibri", size: 22, color: C.slate, ...r });
    }),
  });
}

function bold(text, rest) {
  return pRich([{ text, bold: true, color: C.black }, rest]);
}

function calloutBox(title, lines) {
  // Teal left-border callout
  return [
    new Paragraph({
      spacing: { before: 200, after: 80 },
      shading: { fill: C.tealPale, type: ShadingType.CLEAR },
      border: { left: { style: BorderStyle.SINGLE, size: 12, color: C.teal, space: 8 } },
      indent: { left: 120 },
      children: [new TextRun({ text: title, font: "Calibri", size: 22, bold: true, color: C.teal })],
    }),
    ...lines.map(l => new Paragraph({
      spacing: { after: 60 },
      shading: { fill: C.tealPale, type: ShadingType.CLEAR },
      border: { left: { style: BorderStyle.SINGLE, size: 12, color: C.teal, space: 8 } },
      indent: { left: 120 },
      children: [new TextRun({ text: l, font: "Calibri", size: 21, color: C.slate })],
    })),
    spacer(),
  ];
}

function warningBox(title, lines) {
  return [
    new Paragraph({
      spacing: { before: 200, after: 80 },
      shading: { fill: "FEF3C7", type: ShadingType.CLEAR },
      border: { left: { style: BorderStyle.SINGLE, size: 12, color: C.amber, space: 8 } },
      indent: { left: 120 },
      children: [new TextRun({ text: title, font: "Calibri", size: 22, bold: true, color: C.amber })],
    }),
    ...lines.map(l => new Paragraph({
      spacing: { after: 60 },
      shading: { fill: "FEF3C7", type: ShadingType.CLEAR },
      border: { left: { style: BorderStyle.SINGLE, size: 12, color: C.amber, space: 8 } },
      indent: { left: 120 },
      children: [new TextRun({ text: l, font: "Calibri", size: 21, color: C.slate })],
    })),
    spacer(),
  ];
}

function code(lines) {
  return lines.map(l => new Paragraph({
    spacing: { after: 40, line: 260 },
    shading: { fill: C.codeBg, type: ShadingType.CLEAR },
    indent: { left: 200, right: 200 },
    children: [new TextRun({ text: l || " ", font: "JetBrains Mono, Consolas, Courier New", size: 19, color: C.navyMed })],
  }));
}

function bullet(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 100, line: 280 },
    children: [new TextRun({ text, font: "Calibri", size: 22, color: C.slate })],
  });
}

function bulletBold(b, rest) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 100, line: 280 },
    children: [
      new TextRun({ text: b, font: "Calibri", size: 22, bold: true, color: C.black }),
      new TextRun({ text: rest, font: "Calibri", size: 22, color: C.slate }),
    ],
  });
}

function bullet2(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 1 },
    spacing: { after: 80, line: 260 },
    children: [new TextRun({ text, font: "Calibri", size: 21, color: C.grayText })],
  });
}

function num(text) {
  return new Paragraph({
    numbering: { reference: "numbers", level: 0 },
    spacing: { after: 120, line: 280 },
    children: [new TextRun({ text, font: "Calibri", size: 22, color: C.slate })],
  });
}

function spacer(h = 120) {
  return new Paragraph({ spacing: { after: h }, children: [] });
}

function pb() { return new Paragraph({ children: [new PageBreak()] }); }

// Modern table with alternating rows, no vertical borders
function headerCell(text, w) {
  return new TableCell({
    borders: { top: noBorder, bottom: { style: BorderStyle.SINGLE, size: 4, color: C.teal }, left: noBorder, right: noBorder },
    width: { size: w, type: WidthType.DXA },
    margins: { top: 100, bottom: 100, left: 120, right: 120 },
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, font: "Calibri", size: 20, color: C.navy })] })],
  });
}

function dataCell(text, w, alt) {
  return new TableCell({
    borders: { top: noBorder, bottom: { style: BorderStyle.SINGLE, size: 1, color: C.grayLine }, left: noBorder, right: noBorder },
    width: { size: w, type: WidthType.DXA },
    shading: alt ? { fill: C.grayBg, type: ShadingType.CLEAR } : undefined,
    margins: { top: 70, bottom: 70, left: 120, right: 120 },
    children: [new Paragraph({ children: [new TextRun({ text, font: "Calibri", size: 20, color: C.slate })] })],
  });
}

function codeDataCell(text, w, alt) {
  return new TableCell({
    borders: { top: noBorder, bottom: { style: BorderStyle.SINGLE, size: 1, color: C.grayLine }, left: noBorder, right: noBorder },
    width: { size: w, type: WidthType.DXA },
    shading: alt ? { fill: C.grayBg, type: ShadingType.CLEAR } : undefined,
    margins: { top: 70, bottom: 70, left: 120, right: 120 },
    children: [new Paragraph({ children: [new TextRun({ text, font: "Consolas", size: 19, color: C.navyMed })] })],
  });
}

function table(headers, rows, widths) {
  const tw = widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: tw, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({ children: headers.map((h, i) => headerCell(h, widths[i])) }),
      ...rows.map((row, ri) =>
        new TableRow({ children: row.map((c, ci) => dataCell(c, widths[ci], ri % 2 === 0)) })
      ),
    ],
  });
}

// Stat card row (for key metrics on cover page)
function statCard(label, value, color) {
  return [
    new TableCell({
      borders: { top: { style: BorderStyle.SINGLE, size: 6, color, space: 0 }, bottom: noBorder, left: noBorder, right: noBorder },
      width: { size: 2200, type: WidthType.DXA },
      shading: { fill: C.grayBg, type: ShadingType.CLEAR },
      margins: { top: 160, bottom: 160, left: 160, right: 160 },
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
          children: [new TextRun({ text: value, font: "Calibri", size: 40, bold: true, color })] }),
        new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: label, font: "Calibri", size: 18, color: C.grayText })] }),
      ],
    }),
  ];
}

// ══════════════════════════════════════════════════════════════
// BUILD DOCUMENT
// ══════════════════════════════════════════════════════════════

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Calibri", size: 22, color: C.black } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 40, bold: true, font: "Calibri", color: C.navy },
        paragraph: { spacing: { before: 480, after: 240 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, font: "Calibri", color: C.teal },
        paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Calibri", color: C.navyMed },
        paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [
        { level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 600, hanging: 300 } } } },
        { level: 1, format: LevelFormat.BULLET, text: "\u25CB", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 1200, hanging: 300 } } } },
      ]},
      { reference: "numbers", levels: [
        { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 600, hanging: 360 } } } },
      ]},
    ],
  },
  sections: [
    // ════════════════════════════════════════
    // COVER PAGE
    // ════════════════════════════════════════
    {
      properties: {
        page: { size: { width: PAGE_W, height: 15840 }, margin: { top: 2160, right: MARGIN, bottom: MARGIN, left: MARGIN } },
      },
      children: [
        ...Array(4).fill(null).map(() => spacer(200)),
        // Title block
        new Paragraph({
          spacing: { after: 60 },
          children: [new TextRun({ text: "GRC", font: "Calibri", size: 96, bold: true, color: C.navy })],
        }),
        new Paragraph({
          spacing: { after: 20 },
          children: [new TextRun({ text: "TOOLKIT", font: "Calibri", size: 96, bold: true, color: C.teal })],
        }),
        new Paragraph({
          spacing: { after: 80 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: C.teal, space: 12 } },
          children: [],
        }),
        new Paragraph({
          spacing: { before: 200, after: 60 },
          children: [new TextRun({ text: "Technical Documentation", font: "Calibri", size: 32, color: C.slate })],
        }),
        new Paragraph({
          spacing: { after: 400 },
          children: [new TextRun({ text: "Setup, Configuration & Deployment Guide", font: "Calibri", size: 24, color: C.slateL })],
        }),

        // Stats row
        new Table({
          width: { size: 9200, type: WidthType.DXA },
          columnWidths: [2200, 200, 2200, 200, 2200, 200, 2200],
          rows: [new TableRow({ children: [
            ...statCard("Controls", "437", C.teal),
            new TableCell({ borders: noBorders, width: { size: 200, type: WidthType.DXA }, children: [new Paragraph("")] }),
            ...statCard("Rego Policies", "251", C.navy),
            new TableCell({ borders: noBorders, width: { size: 200, type: WidthType.DXA }, children: [new Paragraph("")] }),
            ...statCard("API Endpoints", "63+", C.green),
            new TableCell({ borders: noBorders, width: { size: 200, type: WidthType.DXA }, children: [new Paragraph("")] }),
            ...statCard("Integrations", "35+", C.amber),
          ]})],
        }),

        spacer(600),

        // Meta info
        new Paragraph({
          children: [
            new TextRun({ text: "Version 0.3.0", font: "Calibri", size: 20, color: C.slateL }),
            new TextRun({ text: "   |   March 2026", font: "Calibri", size: 20, color: C.slateL }),
            new TextRun({ text: "   |   Internal Use Only", font: "Calibri", size: 20, color: C.slateL }),
          ],
        }),
        pb(),
      ],
    },

    // ════════════════════════════════════════
    // MAIN CONTENT
    // ════════════════════════════════════════
    {
      properties: {
        page: { size: { width: PAGE_W, height: 15840 }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } },
      },
      headers: {
        default: new Header({ children: [
          new Paragraph({
            border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: C.grayLine, space: 6 } },
            children: [
              new TextRun({ text: "GRC Toolkit", font: "Calibri", size: 18, bold: true, color: C.navy }),
              new TextRun({ text: "\tTechnical Documentation", font: "Calibri", size: 18, color: C.slateL }),
            ],
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
          }),
        ]}),
      },
      footers: {
        default: new Footer({ children: [
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: "Page ", font: "Calibri", size: 18, color: C.slateL }),
              new TextRun({ children: [PageNumber.CURRENT], font: "Calibri", size: 18, color: C.slateL }),
            ],
          }),
        ]}),
      },
      children: [
        // TABLE OF CONTENTS
        h1("Table of Contents"),
        new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-3" }),
        pb(),

        // ──────────────────────────────────
        // 1. WHAT IS THE GRC TOOLKIT?
        // ──────────────────────────────────
        h1("What is the GRC Toolkit?"),
        p("The GRC Toolkit is an open-source platform that helps security and compliance teams manage governance, risk, and compliance in one place. Instead of juggling spreadsheets and manual checklists, you get automated evidence collection, real-time dashboards, and policy enforcement across your cloud infrastructure."),
        spacer(),
        h2("What It Does"),
        bulletBold("Tracks 437 compliance controls ", "across NIST 800-53, ISO 27001, and SOC 2"),
        bulletBold("Collects evidence automatically ", "from AWS, Azure, and GCP using native APIs"),
        bulletBold("Enforces policies as code ", "using 251 OPA/Rego policies that run continuously"),
        bulletBold("Quantifies risk ", "with Monte Carlo simulations instead of red/yellow/green guesses"),
        bulletBold("Maps controls across frameworks ", "so you assess once and report everywhere"),
        bulletBold("Connects to 35+ security tools ", "like CrowdStrike, Splunk, Okta, Tenable, and more"),
        bulletBold("Provides a customer trust portal ", "so prospects can see your compliance posture"),
        spacer(),
        h2("Technology Stack"),
        table(
          ["Layer", "Technology", "Version"],
          [
            ["Backend", "Python + FastAPI", "3.11+ / 0.109+"],
            ["Frontend", "React + TypeScript + Vite", "19 / 5.9 / 8"],
            ["Database", "PostgreSQL (production) or SQLite (development)", "16.2"],
            ["ORM", "SQLAlchemy", "2.0+"],
            ["Policy Engine", "Open Policy Agent (OPA)", "0.62.1"],
            ["Styling", "Tailwind CSS", "Latest"],
            ["Charts", "Recharts", "Latest"],
            ["Auth", "JWT tokens + bcrypt passwords", "HS256"],
            ["Task Queue", "Celery + Redis", "5.3 / 7.2"],
            ["Containers", "Docker + Docker Compose", "Latest"],
            ["Infrastructure", "Terraform", "1.5+"],
          ],
          [2400, 3600, 3360],
        ),
        pb(),

        // ──────────────────────────────────
        // 2. QUICK START
        // ──────────────────────────────────
        h1("Quick Start"),
        p("Get the toolkit running locally in under 5 minutes. This uses SQLite so you don't need to install PostgreSQL or Docker."),
        spacer(),
        h2("Prerequisites"),
        bullet("Python 3.11 or later"),
        bullet("Node.js 18 or later (only if you want to modify the frontend)"),
        bullet("Git"),
        spacer(),
        h2("Step 1: Clone & Set Up Python"),
        ...code([
          "git clone https://github.com/<your-org>/grc-toolkit.git",
          "cd grc-toolkit",
          "",
          "python3 -m venv .venv",
          "source .venv/bin/activate",
          "pip install -r requirements.txt",
        ]),
        spacer(),
        h2("Step 2: Configure Environment"),
        ...code([
          "cp .env.example .env",
        ]),
        p("Open .env and set these values for local development:"),
        ...code([
          "GRC_DATABASE_URL=sqlite:///grc_toolkit.db",
          "GRC_SECRET_KEY=any-random-string-for-local-dev",
          "# Leave GRC_API_KEYS empty to skip API key auth in dev",
        ]),
        spacer(),
        h2("Step 3: Load Demo Data"),
        ...code([
          "python -m scripts.seed_demo_data",
        ]),
        p("This creates demo users, sample assessments, vendors, evidence records, and policy violations so you have data to explore immediately."),
        spacer(),
        h2("Step 4: Start the Server"),
        ...code([
          "uvicorn api.main:app --reload --host 0.0.0.0 --port 8000",
        ]),
        p("Open http://localhost:8000 in your browser. Log in with:"),
        ...calloutBox("Demo Credentials", [
          "Email: admin@grc-demo.com",
          "Password: demo1234",
        ]),
        pb(),

        // ──────────────────────────────────
        // 3. PROJECT STRUCTURE
        // ──────────────────────────────────
        h1("Project Structure"),
        p("Here's how the codebase is organized. Each folder has a specific job."),
        spacer(),
        table(
          ["Folder", "What It Contains", "When You'd Touch It"],
          [
            ["api/", "FastAPI app, routers, auth, middleware", "Adding or modifying API endpoints"],
            ["api/routers/", "14 route files (auth, dashboard, evidence, etc.)", "Adding new features or endpoints"],
            ["modules/", "Core business logic", "Changing how assessments, risk, or collection works"],
            ["modules/collectors/", "AWS, Azure, GCP evidence collectors", "Adding new cloud checks"],
            ["modules/connectors/", "Connector framework for external tools", "Integrating a new security tool"],
            ["db/", "SQLAlchemy models, sessions, repositories", "Changing database schema"],
            ["config/", "YAML files for frameworks, controls, crosswalks", "Adding or updating compliance controls"],
            ["policies/", "OPA Rego policy files (251 total)", "Adding or updating policy rules"],
            ["frontend/", "React TypeScript SPA source code", "Changing the dashboard UI"],
            ["static/", "Built frontend assets (served by FastAPI)", "After running npm run build"],
            ["terraform/", "IaC modules for AWS, Azure, GCP", "Deploying compliance-enforcing infrastructure"],
            ["tests/", "364 pytest tests", "After any code changes"],
            ["scripts/", "CLI tools for seeding, assessments, etc.", "Running manual operations"],
          ],
          [1800, 4000, 3560],
        ),
        pb(),

        // ──────────────────────────────────
        // 4. ARCHITECTURE
        // ──────────────────────────────────
        h1("Architecture"),
        h2("System Components"),
        p("The toolkit is made up of these services that work together:"),
        spacer(),
        table(
          ["Component", "What It Does", "How It Connects"],
          [
            ["FastAPI App", "Serves the API (63+ endpoints) and the React frontend", "Port 8000, accepts HTTP requests"],
            ["PostgreSQL", "Stores all data (10 tables)", "Internal port 5432, only the API connects to it"],
            ["OPA Server", "Evaluates Rego policies against resource data", "Internal port 8181, called by the API"],
            ["Redis", "Message broker for background tasks", "Internal port 6379, used by Celery workers"],
            ["React SPA", "Dashboard UI served as static files", "Loaded in browser, calls the API"],
          ],
          [2000, 3760, 3600],
        ),
        spacer(),
        h2("How a Request Flows Through the System"),
        p("Every API request passes through these layers in order:"),
        spacer(),
        num("Rate Limiter checks if the client has exceeded their request quota (120/min default)"),
        num("Audit Logger records the request with a unique ID, timestamp, method, path, and client IP"),
        num("Security Headers adds HSTS, X-Frame-Options, and other protective headers to the response"),
        num("CORS validates the request origin against your whitelist"),
        num("Authentication verifies the JWT token or API key"),
        num("Route Handler runs the business logic and returns the response"),
        spacer(),
        ...calloutBox("Every Request Gets Tracked", [
          "All responses include an X-Request-Id header. Use this for debugging and incident response.",
          "Sensitive headers (Authorization, API keys, cookies) are automatically redacted in logs.",
        ]),
        pb(),

        // ──────────────────────────────────
        // 5. COMPLIANCE FRAMEWORKS
        // ──────────────────────────────────
        h1("Compliance Frameworks"),
        p("The toolkit ships with complete control definitions for three major frameworks, plus partial coverage of three more."),
        spacer(),
        h2("Framework Coverage"),
        table(
          ["Framework", "Controls", "Config File", "Policy Files"],
          [
            ["NIST SP 800-53 Rev 5", "293 active controls, 20 families", "config/nist_800_53.yaml (8,474 lines)", "142 Rego policies"],
            ["ISO 27001:2022 Annex A", "93 controls, 4 themes", "config/iso_27001.yaml (2,668 lines)", "93 Rego policies"],
            ["SOC 2 Type II", "51 controls, 13 categories", "config/soc2.yaml (1,972 lines)", "13 Rego policies"],
            ["HIPAA", "64+ controls", "config/frameworks.yaml", "Via crosswalk to NIST"],
            ["CMMC Level 2", "110 controls", "config/frameworks.yaml", "Via crosswalk to NIST"],
            ["PCI DSS", "Varies", "config/frameworks.yaml", "Via crosswalk"],
          ],
          [2600, 2400, 2800, 1560],
        ),
        spacer(),
        h2("NIST 800-53 Control Families"),
        p("All 20 control families are implemented with both YAML definitions and Rego policies:"),
        spacer(),
        table(
          ["Family", "Name", "Policies"],
          [
            ["AC", "Access Control", "3 policies"],
            ["AT", "Awareness and Training", "4 policies"],
            ["AU", "Audit and Accountability", "2 policies"],
            ["CA", "Security Assessment and Authorization", "7 policies"],
            ["CM", "Configuration Management", "1 policy"],
            ["CP", "Contingency Planning", "9 policies"],
            ["IA", "Identification and Authentication", "2 policies"],
            ["IR", "Incident Response", "8 policies"],
            ["MA", "Maintenance", "6 policies"],
            ["MP", "Media Protection", "7 policies"],
            ["PE", "Physical and Environmental Protection", "17 policies"],
            ["PL", "Planning", "8 policies"],
            ["PM", "Program Management", "14 policies"],
            ["PS", "Personnel Security", "9 policies"],
            ["PT", "PII Processing and Transparency", "8 policies"],
            ["RA", "Risk Assessment", "7 policies"],
            ["SA", "System and Services Acquisition", "15 policies"],
            ["SC", "System and Communications Protection", "4 policies"],
            ["SI", "System and Information Integrity", "1 policy"],
            ["SR", "Supply Chain Risk Management", "10 policies"],
          ],
          [1200, 4400, 3760],
        ),
        spacer(),
        h2("ISO 27001:2022 Annex A Themes"),
        table(
          ["Theme", "Name", "Controls", "Policies"],
          [
            ["A.5", "Organizational Controls", "37 (A.5.1 - A.5.37)", "37 policies"],
            ["A.6", "People Controls", "8 (A.6.1 - A.6.8)", "8 policies"],
            ["A.7", "Physical Controls", "14 (A.7.1 - A.7.14)", "14 policies"],
            ["A.8", "Technological Controls", "34 (A.8.1 - A.8.34)", "34 policies"],
          ],
          [1200, 2800, 2800, 2560],
        ),
        spacer(),
        h2("SOC 2 Trust Services Criteria"),
        table(
          ["Category", "Name", "Policy File"],
          [
            ["CC1", "Control Environment", "cc1_control_environment.rego"],
            ["CC2", "Communication and Information", "cc2_communication_information.rego"],
            ["CC3", "Risk Assessment", "cc3_risk_assessment.rego"],
            ["CC4", "Monitoring Activities", "cc4_monitoring_activities.rego"],
            ["CC5", "Control Activities", "cc5_control_activities.rego"],
            ["CC6", "Logical and Physical Access", "cc6_logical_access.rego"],
            ["CC7", "System Operations", "cc7_system_operations.rego"],
            ["CC8", "Change Management", "cc8_change_management.rego"],
            ["CC9", "Risk Mitigation", "cc9_risk_mitigation.rego"],
            ["A1", "Availability", "a1_availability.rego"],
            ["C1", "Confidentiality", "c1_confidentiality.rego"],
            ["PI1", "Processing Integrity", "pi1_processing_integrity.rego"],
            ["P1", "Privacy", "p1_privacy.rego"],
          ],
          [1200, 3600, 4560],
        ),
        spacer(),
        h2("Framework Crosswalks"),
        p("The crosswalks.yaml file contains 521 control mappings across 5 sections. This lets you assess against one framework and automatically see how you map to others."),
        spacer(),
        bullet("NIST 800-53  to  SOC 2"),
        bullet("NIST 800-53  to  ISO 27001"),
        bullet("NIST 800-53  to  HIPAA"),
        bullet("SOC 2  to  ISO 27001"),
        bullet("ISO 27001  to  NIST 800-53"),
        pb(),

        // ──────────────────────────────────
        // 6. API REFERENCE
        // ──────────────────────────────────
        h1("API Reference"),
        p("All endpoints live under /api/v1/. They return JSON and require authentication unless noted."),
        spacer(),

        h2("Authentication"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["POST", "/api/v1/auth/register", "Create a new user account (no auth required)"],
            ["POST", "/api/v1/auth/login", "Log in and receive a JWT token (no auth required)"],
            ["GET", "/api/v1/auth/me", "Get the current user's profile"],
            ["POST", "/api/v1/auth/logout", "Log out (invalidates the session client-side)"],
          ],
          [1000, 3200, 5160],
        ),
        p("JWT tokens expire after 8 hours. Include them in requests as: Authorization: Bearer <token>"),
        spacer(),

        h2("Dashboard"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [["GET", "/api/v1/dashboard/summary", "Returns a real-time overview: framework status, violation counts, vendor risk, integration status, recent activity"]],
          [1000, 3200, 5160],
        ),
        spacer(),

        h2("Evidence Collection"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["POST", "/api/v1/evidence/collect", "Trigger cloud evidence collection (returns 202)"],
            ["GET", "/api/v1/evidence/", "List evidence records with filtering and pagination"],
            ["GET", "/api/v1/evidence/{id}", "Get a single evidence record with raw API data"],
            ["GET", "/api/v1/evidence/{id}/verify", "Verify evidence integrity via SHA-256 hash"],
          ],
          [1000, 3200, 5160],
        ),
        spacer(),

        h2("Assessments"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["POST", "/api/v1/assessments/run", "Start a compliance assessment (returns 202)"],
            ["GET", "/api/v1/assessments/runs", "List all assessment runs with status"],
            ["GET", "/api/v1/assessments/runs/{id}", "Get details for a specific run"],
            ["GET", "/api/v1/assessments/runs/{id}/results", "Get all check results for a run"],
            ["GET", "/api/v1/assessments/remediation/{control_id}", "Get remediation steps for a control"],
            ["GET", "/api/v1/assessments/trend", "Compliance trend data over time"],
          ],
          [1000, 4000, 4360],
        ),
        spacer(),

        h2("Risk Analysis"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["POST", "/api/v1/risk/simulate", "Run Monte Carlo simulation for one threat scenario"],
            ["POST", "/api/v1/risk/portfolio", "Aggregate risk across multiple scenarios"],
            ["POST", "/api/v1/risk/treatments", "Compare cost-effectiveness of risk treatments"],
            ["GET", "/api/v1/risk/scenarios", "List predefined threat scenarios"],
          ],
          [1000, 3200, 5160],
        ),
        spacer(),

        h2("Frameworks"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["GET", "/api/v1/frameworks/", "List all supported frameworks"],
            ["GET", "/api/v1/frameworks/{id}", "Get framework details with control families"],
            ["GET", "/api/v1/frameworks/{id}/controls", "Get all controls in a framework"],
            ["POST", "/api/v1/frameworks/crosswalk", "Map a control to equivalent controls in other frameworks"],
          ],
          [1000, 3600, 4760],
        ),
        spacer(),

        h2("Vendors"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["POST", "/api/v1/vendors/", "Add a new vendor"],
            ["GET", "/api/v1/vendors/", "List vendors with pagination"],
            ["GET", "/api/v1/vendors/dashboard", "Vendor risk dashboard with distribution"],
            ["GET", "/api/v1/vendors/needing-assessment", "Vendors overdue for assessment"],
            ["GET", "/api/v1/vendors/{id}", "Get vendor details"],
            ["PUT", "/api/v1/vendors/{id}", "Update vendor (only allowlisted fields)"],
          ],
          [1000, 3600, 4760],
        ),
        spacer(),

        h2("Policies (OPA)"),
        table(
          ["Method", "Endpoint", "What It Does"],
          [
            ["POST", "/api/v1/policies/evaluate", "Evaluate a resource against OPA policies"],
            ["GET", "/api/v1/policies/violations", "List open violations with severity filtering"],
            ["POST", "/api/v1/policies/violations/{id}/resolve", "Mark a violation as resolved"],
            ["GET", "/api/v1/policies/bundles", "List available policy bundles"],
          ],
          [1000, 3800, 4560],
        ),
        spacer(),

        h2("Other Endpoints"),
        table(
          ["Router", "Prefix", "What It Does"],
          [
            ["Integrations", "/api/v1/integrations", "Browse 35-tool catalog, connect, sync, disconnect"],
            ["Exports", "/api/v1/exports", "Download POA&M documents, summaries, audit packages"],
            ["Tool Config", "/api/v1/tool-config", "Configure credentials for connected tools"],
            ["Data Silos", "/api/v1/data-silos", "Scan S3, GitHub, SharePoint for PII/PHI"],
            ["Trust Portal", "/api/v1/trust", "Public compliance page (no auth required)"],
            ["Settings", "/api/v1/settings", "Org settings, notifications, API keys"],
          ],
          [2000, 2800, 4560],
        ),
        pb(),

        // ──────────────────────────────────
        // 7. DATABASE
        // ──────────────────────────────────
        h1("Database"),
        p("The app uses SQLAlchemy 2.0 with 10 tables. All primary keys are UUIDs stored as strings for SQLite/PostgreSQL portability. Tables are created automatically on startup."),
        spacer(),
        h2("Tables"),
        table(
          ["Table", "What It Stores", "Key Fields"],
          [
            ["users", "Login accounts", "email (unique), hashed_password, role (analyst/admin)"],
            ["audit_logs", "Every data change", "actor, action, resource_type, changes (JSON)"],
            ["evidence_records", "Collected cloud evidence", "control_id, provider, data (JSON), sha256_hash"],
            ["assessment_runs", "Assessment executions", "framework, status, pass_rate, summary (JSON)"],
            ["assessment_results", "Individual check results", "run_id (FK), control_id, status, findings (JSON)"],
            ["framework_definitions", "Framework metadata", "key, version, control_count, data (JSON)"],
            ["vendor_records", "Vendor risk tracking", "risk_score, risk_level, certifications (JSON)"],
            ["policy_violations", "OPA violations", "policy_id, severity, status (open/resolved)"],
            ["asset_records", "Cloud resource inventory", "provider, service, resource_type, tags (JSON)"],
            ["data_sources", "Connected data sources", "name, type, connection_status, last_sync"],
          ],
          [2400, 2800, 4160],
        ),
        spacer(),
        h2("Key Indexes"),
        bullet("evidence_records: control_id, provider, account_id, collected_at"),
        bullet("assessment_results: run_id, control_id, status"),
        bullet("users: email (unique)"),
        bullet("policy_violations: policy_id, status"),
        pb(),

        // ──────────────────────────────────
        // 8. FRONTEND
        // ──────────────────────────────────
        h1("Frontend Dashboard"),
        p("The frontend is a React single-page app with TypeScript, Tailwind CSS, and Recharts. It's served as static files by FastAPI - no separate frontend server needed."),
        spacer(),
        h2("Pages"),
        table(
          ["Route", "Page", "What It Shows"],
          [
            ["/", "Landing", "Public marketing page with feature overview"],
            ["/login", "Login", "Email + password authentication"],
            ["/register", "Register", "New user sign-up"],
            ["/dashboard", "Dashboard", "Real-time compliance posture with charts"],
            ["/frameworks", "Frameworks", "Browse frameworks, families, and crosswalks"],
            ["/assessments", "Assessments", "Run assessments and view results"],
            ["/evidence", "Evidence", "Browse and verify collected evidence"],
            ["/risk", "Risk", "Monte Carlo simulations and portfolio analysis"],
            ["/vendors", "Vendors", "Vendor inventory and risk scoring"],
            ["/integrations", "Integrations", "Connect and manage 35+ tools"],
            ["/poam", "POA&M", "Plan of Action and Milestones tracking"],
            ["/data-silos", "Data Silos", "Data discovery and classification"],
            ["/trust-hub", "Trust Hub", "Admin view of the trust portal"],
            ["/trust", "Trust Portal", "Public compliance transparency page"],
            ["/settings", "Settings", "Organization config and API keys"],
            ["/tool-config", "Tool Config", "Credential management for integrations"],
          ],
          [1800, 1800, 5760],
        ),
        spacer(),
        h2("Building the Frontend"),
        ...code([
          "cd frontend",
          "npm install",
          "npm run dev          # Dev server with hot-reload on port 5173",
          "npm run build        # Production build to ../static/",
        ]),
        p("After building, restart the FastAPI server and the new frontend is live."),
        pb(),

        // ──────────────────────────────────
        // 9. DOCKER DEPLOYMENT
        // ──────────────────────────────────
        h1("Docker Deployment"),
        p("For production, use Docker Compose to run the full stack: API, PostgreSQL, OPA, and Redis."),
        spacer(),
        h2("Services"),
        table(
          ["Service", "Image", "Exposed Port", "Health Check"],
          [
            ["api", "Built from Dockerfile", "127.0.0.1:8000", "GET /health"],
            ["db", "postgres:16.2-alpine", "None (internal only)", "pg_isready"],
            ["opa", "openpolicyagent/opa:0.62.1", "None (internal only)", "GET /health"],
            ["redis", "redis:7.2-alpine", "None (internal only)", "redis-cli ping"],
          ],
          [1400, 2800, 2560, 2600],
        ),
        spacer(),

        h2("Deploy in 4 Steps"),
        spacer(),
        h3("1. Create environment file"),
        ...code([
          "cp .env.example .env",
        ]),
        spacer(),
        h3("2. Set required secrets"),
        ...code([
          "# Generate a strong password for PostgreSQL",
          "POSTGRES_PASSWORD=$(python3 -c \"import secrets; print(secrets.token_urlsafe(24))\")",
          "",
          "# Generate a strong Redis password",
          "REDIS_PASSWORD=$(python3 -c \"import secrets; print(secrets.token_urlsafe(24))\")",
          "",
          "# Generate API key for programmatic access",
          "python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"",
          "",
          "# Generate JWT signing key",
          "python3 -c \"import secrets; print(secrets.token_urlsafe(64))\"",
        ]),
        p("Put these values in your .env file."),
        spacer(),
        h3("3. Launch the stack"),
        ...code([
          "docker compose up -d",
          "docker compose ps          # Check all services are healthy",
          "docker compose logs -f api # Watch API logs",
        ]),
        spacer(),
        h3("4. Seed demo data (optional)"),
        ...code([
          "docker compose exec api python -m scripts.seed_demo_data",
        ]),
        spacer(),

        ...calloutBox("Security Features Built In", [
          "Non-root user inside all containers",
          "Read-only filesystem with /tmp tmpfs",
          "Database, OPA, and Redis not exposed to host network",
          "API bound to localhost only (use a reverse proxy for external access)",
          "Pinned image digests for supply chain security",
        ]),
        pb(),

        // ──────────────────────────────────
        // 10. PRODUCTION
        // ──────────────────────────────────
        h1("Production Configuration"),

        h2("Reverse Proxy"),
        p("Never expose the API container directly to the internet. Put Nginx, Caddy, or a cloud load balancer in front of it."),
        spacer(),
        h3("Nginx Example"),
        ...code([
          "server {",
          "    listen 443 ssl http2;",
          "    server_name grc.example.com;",
          "",
          "    ssl_certificate     /etc/ssl/certs/grc.crt;",
          "    ssl_certificate_key /etc/ssl/private/grc.key;",
          "",
          "    location / {",
          "        proxy_pass http://127.0.0.1:8000;",
          "        proxy_set_header Host $host;",
          "        proxy_set_header X-Real-IP $remote_addr;",
          "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
          "        proxy_set_header X-Forwarded-Proto $scheme;",
          "    }",
          "}",
        ]),
        spacer(),

        h2("Environment Variables"),
        table(
          ["Variable", "Required?", "Default", "What It Does"],
          [
            ["GRC_DATABASE_URL", "Yes", "sqlite:///grc_toolkit.db", "Database connection string"],
            ["GRC_SECRET_KEY", "Yes", "dev-secret", "JWT signing key (use 64+ random chars)"],
            ["GRC_API_KEYS", "Production", "(empty)", "Comma-separated API keys"],
            ["GRC_OPA_URL", "No", "http://opa:8181", "OPA server address"],
            ["GRC_CORS_ORIGINS", "No", "*", "Allowed CORS origins"],
            ["GRC_RATE_LIMIT_RPM", "No", "120", "Requests per minute per IP"],
            ["GRC_RATE_LIMIT_BURST", "No", "20", "Burst capacity"],
            ["GRC_ENABLE_DOCS", "No", "false", "Show Swagger UI at /docs"],
            ["POSTGRES_PASSWORD", "Docker", "-", "PostgreSQL password"],
            ["REDIS_PASSWORD", "Docker", "-", "Redis password"],
            ["GRC_SLACK_WEBHOOK_URL", "No", "-", "Slack alerts"],
            ["GRC_SMTP_SERVER", "No", "-", "Email alerts (server)"],
            ["GRC_SMTP_PORT", "No", "587", "Email alerts (port)"],
            ["GRC_SMTP_SENDER", "No", "-", "Email alerts (from address)"],
          ],
          [2400, 1000, 2160, 3800],
        ),
        spacer(),

        h2("Production Checklist"),
        ...warningBox("Do These Before Going Live", [
          "Set GRC_API_KEYS with strong, randomly-generated keys",
          "Set GRC_SECRET_KEY to 64+ random characters",
          "Set GRC_ENABLE_DOCS=false",
          "Set GRC_CORS_ORIGINS to your specific domain(s)",
          "Use PostgreSQL with SSL (sslmode=require), never SQLite",
          "Put behind a TLS-terminating reverse proxy",
          "Configure log aggregation (CloudWatch, Datadog, ELK)",
          "Set up automated daily database backups",
          "Enable credential rotation for cloud provider access",
          "Configure Slack or email notifications for critical findings",
        ]),
        pb(),

        // ──────────────────────────────────
        // 11. SECURITY
        // ──────────────────────────────────
        h1("Security Architecture"),

        h2("Authentication"),
        table(
          ["Method", "Used For", "How It Works"],
          [
            ["JWT Bearer Token", "Dashboard UI, user sessions", "HS256 signed, 8-hour expiry, bcrypt passwords"],
            ["API Key (X-API-Key)", "Scripts, service-to-service", "Constant-time comparison, set via env var"],
            ["OAuth2 Password Grant", "Login endpoint", "Returns JWT token on success"],
          ],
          [2400, 2800, 4160],
        ),
        spacer(),

        h2("Security Headers"),
        p("Every response includes these protective headers automatically:"),
        table(
          ["Header", "Value", "What It Prevents"],
          [
            ["X-Content-Type-Options", "nosniff", "MIME-type confusion attacks"],
            ["X-Frame-Options", "DENY", "Clickjacking"],
            ["X-XSS-Protection", "1; mode=block", "Cross-site scripting"],
            ["Strict-Transport-Security", "max-age=31536000", "HTTP downgrade attacks"],
            ["Permissions-Policy", "geolocation=(), camera=()", "Unwanted browser API access"],
            ["Referrer-Policy", "strict-origin-when-cross-origin", "Referrer data leakage"],
          ],
          [3000, 3200, 3160],
        ),
        spacer(),

        h2("Rate Limiting"),
        bullet("Token bucket algorithm: 120 requests/min per IP, 20 burst capacity"),
        bullet("Returns HTTP 429 with Retry-After header when exceeded"),
        bullet("Zero database overhead (tracked in memory)"),
        bullet("Configurable via GRC_RATE_LIMIT_RPM and GRC_RATE_LIMIT_BURST"),
        spacer(),

        h2("Audit Trail"),
        bullet("Every request logged: timestamp, request ID, method, path, client IP, status, duration"),
        bullet("Auth headers automatically redacted in logs"),
        bullet("Database changes tracked in audit_logs table with before/after snapshots"),
        bullet("All responses include X-Request-Id for traceability"),
        pb(),

        // ──────────────────────────────────
        // 12. POLICY-AS-CODE
        // ──────────────────────────────────
        h1("Policy-as-Code (OPA)"),
        p("The toolkit uses Open Policy Agent to continuously evaluate your infrastructure against compliance rules written in Rego."),
        spacer(),

        h2("How It Works"),
        num("You send resource data to POST /api/v1/policies/evaluate"),
        num("The API forwards it to OPA at http://opa:8181"),
        num("OPA evaluates the matching Rego policies"),
        num("Violations are returned and stored in the policy_violations table"),
        num("Unresolved violations show up on the dashboard and trigger alerts"),
        spacer(),

        h2("Policy Organization"),
        ...code([
          "policies/",
          "  nist-800-53/          # 142 policies across 20 families",
          "    ac/  at/  au/  ca/  cm/  cp/  ia/  ir/  ma/  mp/",
          "    pe/  pl/  pm/  ps/  pt/  ra/  sa/  sc/  si/  sr/",
          "  iso-27001/            # 93 policies across 4 themes",
          "    a5/  a6/  a7/  a8/",
          "  soc2/                 # 13 policies (all categories)",
          "  terraform/            # 3 cloud baseline policies",
        ]),
        spacer(),

        h2("Terraform Policy Validation"),
        p("Validate Terraform plans before applying them:"),
        ...code([
          "terraform plan -out=plan.tfplan",
          "terraform show -json plan.tfplan > plan.json",
          "conftest test plan.json -p policies/terraform/",
        ]),
        pb(),

        // ──────────────────────────────────
        // 13. INTEGRATIONS
        // ──────────────────────────────────
        h1("Integrations"),
        p("The toolkit connects to 35+ security tools. Each integration maps to the compliance controls it helps satisfy."),
        spacer(),
        table(
          ["Category", "Tools", "Controls Covered"],
          [
            ["Cloud Providers", "AWS, Azure, GCP, Prisma Cloud", "AC, AU, CM, SC, SI"],
            ["EDR / Endpoints", "CrowdStrike, Defender, SentinelOne", "SI-3, SI-4, IR-4"],
            ["Identity & Access", "Okta, Entra ID, CyberArk, SailPoint", "AC-2, AC-6, IA-2, IA-5"],
            ["Vulnerability Scanners", "Tenable, Qualys, Rapid7, Wiz", "RA-5, SI-2, CM-6"],
            ["SIEM / Monitoring", "Sentinel, Splunk, Elastic, Datadog", "AU-6, SI-4, IR-4, IR-6"],
            ["DevSecOps", "GitHub, GitLab, Snyk", "SA-11, CM-3, SI-2"],
            ["GRC Platforms", "ServiceNow, Drata, Vanta", "CA-2, CA-7, PM-9"],
            ["Alerting", "PagerDuty, Slack, Jira", "IR-4, IR-6, IR-7"],
            ["AI / LLM", "OpenAI, Anthropic, Gemini, Ollama", "Custom analysis"],
          ],
          [2400, 3600, 3360],
        ),
        spacer(),
        p("Configure tool credentials through the Tool Config page in the dashboard, or programmatically via the /api/v1/tool-config API."),
        pb(),

        // ──────────────────────────────────
        // 14. TERRAFORM
        // ──────────────────────────────────
        h1("Cloud Infrastructure (Terraform)"),
        p("These Terraform modules deploy compliance-enforcing infrastructure that the toolkit then monitors."),
        spacer(),
        h2("AWS Modules"),
        table(
          ["Module", "What It Creates", "Controls"],
          [
            ["secure-account-baseline", "CloudTrail, GuardDuty, Security Hub, SNS alerts", "AU-2, AU-3, AU-6, SI-4, IR-6"],
            ["compliant-vpc", "VPC, subnets, flow logs, NAT, default-deny SGs", "SC-7, AC-4, AU-2, SC-8"],
            ["iam-baseline", "Auditor role, root account alerts, MFA enforcement", "AC-2, AC-6, IA-2, IA-5"],
          ],
          [2600, 3760, 3000],
        ),
        spacer(),
        h2("Azure & GCP Modules"),
        table(
          ["Module", "What It Creates", "Controls"],
          [
            ["Azure: secure-subscription-baseline", "Log Analytics, diagnostics, storage encryption", "AU-2, AU-3, SC-28, SI-4"],
            ["GCP: secure-project-baseline", "Audit log sink, org policies, OS login", "AU-2, AC-2, CM-6, CM-7"],
          ],
          [3200, 3360, 2800],
        ),
        spacer(),
        h2("Usage"),
        ...code([
          "cd terraform/modules/aws/secure-account-baseline",
          "terraform init",
          "terraform plan -out=plan.tfplan",
          "terraform apply plan.tfplan",
        ]),
        pb(),

        // ──────────────────────────────────
        // 15. CI/CD
        // ──────────────────────────────────
        h1("CI/CD Pipeline"),
        p("GitHub Actions runs these checks on every push and pull request:"),
        spacer(),
        table(
          ["Check", "Tool", "Must Pass"],
          [
            ["Linting", "ruff check", "Zero violations"],
            ["Type checking", "mypy", "No type errors"],
            ["Unit tests", "pytest + coverage", "All pass, min 60% coverage"],
            ["Security analysis", "bandit (SAST)", "No high/critical findings"],
            ["Dependency audit", "pip-audit", "No known CVEs"],
            ["Container scan", "trivy", "No critical vulnerabilities"],
            ["Secret detection", "gitleaks", "No leaked credentials"],
            ["Policy tests", "opa test -v", "All Rego tests pass"],
            ["Policy formatting", "opa fmt --diff", "Consistent formatting"],
            ["Terraform validation", "terraform validate", "Valid HCL syntax"],
            ["Terraform compliance", "conftest verify", "Plans pass policies"],
          ],
          [2400, 2600, 4360],
        ),
        spacer(),
        ...calloutBox("Compliance Gate", [
          "A separate workflow blocks PRs that modify terraform/ or policies/ until",
          "all security checks pass AND a policy review approval is obtained.",
        ]),
        pb(),

        // ──────────────────────────────────
        // 16. OPERATIONS
        // ──────────────────────────────────
        h1("Operations & Maintenance"),

        h2("Health Check"),
        ...code([
          "curl http://localhost:8000/health",
          '# Returns: {"status": "healthy"}',
        ]),
        p("Use this for load balancer health checks and uptime monitoring."),
        spacer(),

        h2("Backups"),
        ...code([
          "# Daily backup",
          "docker compose exec db pg_dump -U grc grc_toolkit > backup_$(date +%Y%m%d).sql",
          "",
          "# Restore",
          "docker compose exec -T db psql -U grc grc_toolkit < backup_20260314.sql",
        ]),
        spacer(),

        h2("Scaling"),
        bulletBold("Horizontal: ", "Run multiple API containers behind a load balancer. The app is stateless (JWT + DB)."),
        bulletBold("Database: ", "Use managed PostgreSQL (RDS, Cloud SQL) with read replicas for dashboard queries."),
        bulletBold("Workers: ", "Scale Celery workers independently for evidence collection and assessment jobs."),
        bulletBold("Storage: ", "Configure S3/GCS/Azure Blob for evidence files in large deployments."),
        spacer(),

        h2("CLI Scripts"),
        table(
          ["Script", "What It Does", "How to Run It"],
          [
            ["seed_demo_data.py", "Populate demo data", "python -m scripts.seed_demo_data"],
            ["run_assessment.py", "Run a compliance assessment", "python scripts/run_assessment.py --framework nist_800_53"],
            ["run_collection.py", "Collect cloud evidence", "python scripts/run_collection.py --provider aws"],
            ["run_risk_analysis.py", "Monte Carlo simulation", "python scripts/run_risk_analysis.py --scenarios data_breach"],
            ["generate_demo_exports.py", "Generate sample reports", "python scripts/generate_demo_exports.py"],
          ],
          [2600, 2400, 4360],
        ),
        ...calloutBox("Important", [
          "Always run scripts from the project root directory with the virtual environment active,",
          "or use python -m scripts.<name> syntax to ensure imports work correctly.",
        ]),
        pb(),

        // ──────────────────────────────────
        // 17. TROUBLESHOOTING
        // ──────────────────────────────────
        h1("Troubleshooting"),
        spacer(),
        table(
          ["Problem", "Cause", "Fix"],
          [
            ["ModuleNotFoundError: api", "Running from wrong directory", "cd to project root, use python -m scripts.<name>"],
            [".venv/bin/python: no such file", "Not in project directory", "cd /path/to/grc-toolkit first"],
            ["Connection refused on :8000", "Server not running", "uvicorn api.main:app --reload"],
            ["401 Unauthorized", "Expired or missing JWT token", "Log in again at /api/v1/auth/login"],
            ["OPA connection failed", "OPA container not running", "docker compose up -d opa"],
            ["Database locked (SQLite)", "Multiple processes writing", "Switch to PostgreSQL for production"],
            ["bcrypt import error", "Missing dependency", "pip install passlib[bcrypt]"],
            ["Tests fail on Python 3.9", "Code uses datetime.UTC (3.11+)", "Upgrade to Python 3.11+"],
            ["Wrong demo password", "Seed data not loaded", "python -m scripts.seed_demo_data"],
          ],
          [2600, 2600, 4160],
        ),
        spacer(),
        h2("Debug Mode"),
        p("Enable Swagger docs and verbose logging for debugging:"),
        ...code([
          "GRC_ENABLE_DOCS=true uvicorn api.main:app --reload --log-level debug",
          "",
          "# Then visit http://localhost:8000/docs for the interactive API explorer",
        ]),
        pb(),

        // ──────────────────────────────────
        // 18. EXTENDING
        // ──────────────────────────────────
        h1("Extending the Toolkit"),

        h2("Add a New Control Assertion"),
        num("Define the check in config/frameworks.yaml under the control"),
        num("Write the assertion function in modules/control_assessor.py"),
        num("Add a Rego policy in policies/<framework>/<family>/"),
        num("Add test coverage in tests/"),
        spacer(),

        h2("Add a New Connector"),
        num("Subclass BaseConnector in modules/connectors/"),
        num("Implement validate_config(), collect(), health_check()"),
        num("Register with ConnectorRegistry"),
        num("Add credential fields to api/routers/tool_config.py"),
        spacer(),

        h2("Add a New API Router"),
        num("Create the router in api/routers/<name>.py"),
        num("Import and register in api/main.py with app.include_router()"),
        num("Add Pydantic schemas in api/schemas.py"),
        num("Add tests in tests/test_api.py"),
        spacer(),

        h2("Add a New Framework"),
        num("Create config/<framework_key>.yaml with controls"),
        num("Add crosswalk entries to config/crosswalks.yaml"),
        num("Create Rego policies in policies/<framework>/"),
        num("Add assertions in modules/control_assessor.py"),
        num("Add tests"),
        spacer(300),

        // End
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 400 },
          border: { top: { style: BorderStyle.SINGLE, size: 2, color: C.grayLine, space: 12 } },
          children: [new TextRun({ text: "End of Document", font: "Calibri", size: 20, italics: true, color: C.slateL })],
        }),
      ],
    },
  ],
});

// ── Write ──
Packer.toBuffer(doc).then(buffer => {
  const out = "/Users/jsn/Coding/GitHub/grc-toolkit/GRC_Toolkit_Technical_Documentation.docx";
  fs.writeFileSync(out, buffer);
  console.log(`Written: ${out}`);
  console.log(`Size: ${(buffer.length / 1024).toFixed(1)} KB`);
});
