const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 3100;
const BASE_RPC = "https://mainnet.base.org";

function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    serveFile(
      res,
      path.join(__dirname, "index.html"),
      "text/html; charset=utf-8"
    );
    return;
  }

  if (req.method === "POST" && req.url === "/rpc") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const options = new URL(BASE_RPC);
      const proxyReq = require("https").request(
        {
          hostname: options.hostname,
          port: 443,
          path: options.pathname,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
          },
        },
        (proxyRes) => {
          let responseBody = "";
          proxyRes.on("data", (chunk) => {
            responseBody += chunk;
          });
          proxyRes.on("end", () => {
            res.writeHead(proxyRes.statusCode, {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
            });
            res.end(responseBody);
          });
        }
      );
      proxyReq.on("error", (err) => {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      });
      proxyReq.write(body);
      proxyReq.end();
    });
    return;
  }

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    res.end();
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`Aegis Dashboard running at http://localhost:${PORT}`);
});
