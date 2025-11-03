/**
 * Minimal static file server for PKCE demo
 *
 * This server exists ONLY to serve static files locally.
 * It performs NO auth logic — all OAuth/PKCE happens client-side.
 *
 * This demonstrates the "portable" advantage of PKCE SPAs:
 * the same static files could be served from any CDN, S3 bucket,
 * or dev server without any backend auth dependencies.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 8080;

/** @type {Record<string, string>} */
const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
};

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  // Parse URL to strip query parameters (OAuth callback URLs have long query strings)
  const parsedUrl = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  let pathname = parsedUrl.pathname;

  // Redirect root to /demo/
  if (pathname === '/') {
    res.writeHead(302, { 'Location': '/demo/' });
    res.end();
    return;
  }

  // Build file path
  // Serve library file (pkce.js) from root, everything else from /demo
  let filePath;
  if (pathname === '/pkce.js') {
    // Library file at root
    filePath = path.join(__dirname, pathname);
  } else {
    // Demo files from /demo directory
    filePath = path.join(__dirname, pathname);
  }

  // Check if path is a directory and append index.html
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  } else if (pathname === '/' || pathname.endsWith('/')) {
    // If path doesn't exist but looks like a directory, try index.html
    filePath = path.join(filePath, 'index.html');
  }

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

server.listen(PORT, () => {
  console.log(`\n🚀 PKCE Demo Server running at http://localhost:${PORT}`);
  console.log(`\n📋 Remember: This server does NO auth. All PKCE happens client-side.\n`);
});
