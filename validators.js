// Bloqueo de hosts peligrosos
const FORBIDDEN_HOSTS = [
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "[::1]",
  "169.254.169.254",
  "metadata.google.internal",
];

const FORBIDDEN_PATTERNS = [
  /^10\./, // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./, // 172.16.0.0/12
  /^192\.168\./, // 192.168.0.0/16
  /^127\./, // loopback
  /^169\.254\./, // link-local
  /^0\./, // 0.0.0.0/8
];

function validateUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { safe: false, reason: "URL inválida" };
  }

  // Solo HTTP y HTTPS
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return {
      safe: false,
      reason: "Protocolo no permitido. Solo http y https.",
    };
  }

  const host = parsed.hostname.toLowerCase();

  if (FORBIDDEN_HOSTS.includes(host)) {
    return { safe: false, reason: "Host bloqueado por seguridad" };
  }

  if (FORBIDDEN_PATTERNS.some((p) => p.test(host))) {
    return { safe: false, reason: "IP privada bloqueada por seguridad" };
  }

  return { safe: true, url: parsed.href };
}

module.exports = { validateUrl };
