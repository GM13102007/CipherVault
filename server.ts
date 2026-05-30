import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import https from "https";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function downloadFile(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = (currentUrl: string) => {
      https.get(currentUrl, (response) => {
        if (response.statusCode === 301 || response.statusCode === 302) {
          if (response.headers.location) {
            request(response.headers.location);
            return;
          }
        }
        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: status code ${response.statusCode}`));
          return;
        }
        const file = fs.createWriteStream(dest);
        response.pipe(file);
        file.on('finish', () => {
          file.close();
          resolve();
        });
      }).on('error', (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
    };
    request(url);
  });
}

async function ensurePdfJsLocal() {
  const publicDir = path.join(process.cwd(), 'public');
  if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
  }

  const pdfJsDest = path.join(publicDir, 'pdf.min.js');
  const pdfWorkerDest = path.join(publicDir, 'pdf.worker.min.js');

  const pdfJsUrl = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
  const pdfWorkerUrl = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

  try {
    if (!fs.existsSync(pdfJsDest)) {
      console.log(`[local-pdfjs] Downloading ${pdfJsUrl}...`);
      await downloadFile(pdfJsUrl, pdfJsDest);
      console.log('[local-pdfjs] Successfully downloaded pdf.min.js');
    }
    if (!fs.existsSync(pdfWorkerDest)) {
      console.log(`[local-pdfjs] Downloading ${pdfWorkerUrl}...`);
      await downloadFile(pdfWorkerUrl, pdfWorkerDest);
      console.log('[local-pdfjs] Successfully downloaded pdf.worker.min.js');
    }
  } catch (err: any) {
    console.error('[local-pdfjs] Failed to cache pdfjs locally:', err.message);
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Ensure PDF.js files are locally cached for standalone offline-equivalent capabilities
  await ensurePdfJsLocal();

  // JSON parsing middleware
  app.use(express.json());

  // API Health check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
