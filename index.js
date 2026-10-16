require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares para la seguridad.
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// Rate limiting global de usuario.
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 100,
    standardHeaders: "draft-7",
    message: { error: "Demasiadas peticiones. Intenta en un minuto." },
  }),
);

// Endpoint raíz
app.get("/", (req, res) => {
  res.json({
    name: "Galileus API",
    version: "1.0.0",
    description: "API de análisis pasivo de seguridad web",
    endpoints: {
      health: "GET /health",
      scan: "POST /scan (próximamente)",
    },
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

const server = app.listen(PORT, () => {
  console.log(`Galileus API corriendo en http://localhost:${PORT}`);
});

server.on("error", (err) => {
  console.error("Error al iniciar el server:", err.message);
  console.error("Código:", err.code);
  process.exit(1);
});
