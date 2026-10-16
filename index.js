require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { analyze } = require("./analyzer");
const { validateUrl } = require("./validators");

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares de seguridad
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// Rate limiting global
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 100,
    standardHeaders: "draft-7",
    message: { error: "Demasiadas peticiones. Intenta en un minuto." },
  }),
);

// Rate limiting específico para /scan
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  message: { error: "Límite de escaneos alcanzado. Espera un minuto." },
});

// Middleware de API Key
function requireApiKey(req, res, next) {
  const provided = req.headers["x-api-key"];
  const expected = process.env.API_KEY;

  if (!provided || provided !== expected) {
    return res.status(401).json({ error: "API key inválida o ausente" });
  }
  next();
}

// Endpoint raíz
app.get("/", (req, res) => {
  res.json({
    name: "Galileus API",
    version: "1.0.0",
    description: "API de análisis pasivo de seguridad web",
    endpoints: {
      health: "GET /health",
      scan: "POST /scan (requiere header x-api-key)",
    },
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Endpoint de análisis
app.post("/scan", requireApiKey, scanLimiter, async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Falta el campo 'url' (string)" });
  }

  // Validación SSRF
  const validation = validateUrl(url);
  if (!validation.safe) {
    return res.status(400).json({ error: validation.reason });
  }

  try {
    const report = await analyze(validation.url);
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// manejo de errores
const server = app.listen(PORT, () => {
  console.log(`Galileus API corriendo en http://localhost:${PORT}`);
});

server.on("error", (err) => {
  console.error("Error al iniciar el server:", err.message);
  console.error("Código:", err.code);
  process.exit(1);
});
