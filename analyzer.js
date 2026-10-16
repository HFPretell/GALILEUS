const axios = require("axios");
const {
  checkHttps,
  checkSecurityHeaders,
  checkServerLeak,
  checkInsecureCookies,
} = require("./checks");

// petición HTTP a la URL objetivo y devuelve un reporte completo
async function analyze(url) {
  const findings = [];

  const target = url.startsWith("http") ? url : `https://${url}`;

  let response;
  try {
    response = await axios.get(target, {
      timeout: 8000,
      maxContentLength: 2 * 1024 * 1024, // 2 MB máximo
      maxRedirects: 3,
      validateStatus: () => true,
      headers: {
        "User-Agent": "Galileus-Scanner/1.0",
      },
    });
  } catch (err) {
    throw new Error(`No se pudo conectar a ${target}: ${err.message}`);
  }

  // Ejecución de todos los checks
  const httpsFinding = checkHttps(target);
  if (httpsFinding) findings.push(httpsFinding);

  findings.push(...checkSecurityHeaders(response.headers));

  const serverFinding = checkServerLeak(response.headers);
  if (serverFinding) findings.push(serverFinding);

  findings.push(...checkInsecureCookies(response.headers));

  // calculo del score
  const score = calculateScore(findings);

  return {
    url: target,
    status: response.status,
    score,
    summary: {
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
    },
    findings,
  };
}

// Score de 0 a 100 (empieza en 100 y resta puntos por severidad)
function calculateScore(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === "high") score -= 20;
    if (f.severity === "medium") score -= 10;
    if (f.severity === "low") score -= 5;
  }
  return Math.max(0, score);
}

module.exports = { analyze };
