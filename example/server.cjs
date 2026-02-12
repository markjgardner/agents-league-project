// ─────────────────────────────────────────────────────────────────────
// INTENTIONALLY INSECURE HTTP SERVER — demo only
// This server omits all security headers and exposes /.env.
// It is meant to be scanned by the RedTeam Agent http-scan scanner.
// DO NOT deploy this anywhere — it is for localhost CI demos only.
// ─────────────────────────────────────────────────────────────────────

const http = require("node:http");

const PORT = process.env.DEMO_PORT || 4200;

const server = http.createServer((req, res) => {
  // No security headers set — intentionally insecure

  if (req.url === "/.env") {
    // Exposed sensitive path (intentional for demo)
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("FAKE_SECRET=not_a_real_secret\n");
    return;
  }

  if (req.url === "/.git/config") {
    // Exposed git config (intentional for demo)
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("[core]\n\trepositoryformatversion = 0\n");
    return;
  }

  if (req.url === "/debug") {
    // Exposed debug endpoint (intentional for demo)
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ debug: true, env: "demo" }));
    return;
  }

  res.writeHead(200, { "Content-Type": "text/html" });
  res.end("<h1>Example App</h1><p>Intentionally insecure demo server.</p>\n");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Demo server listening on http://127.0.0.1:${PORT}`);
});
