// Checks de seguridad de Galileus

function checkHttps(url) {
  if (!url.startsWith("https://")) {
    return {
      type: "no-https",
      severity: "high",
      title: "El sitio no usa HTTPS",
      description:
        "La URL no utiliza HTTPS, lo que permite interceptar el tráfico en texto plano.",
      remediation:
        "Configura un certificado TLS y redirige todo el tráfico HTTP a HTTPS.",
    };
  }
  return null;
}

function checkSecurityHeaders(headers) {
  const findings = [];

  const requiredHeaders = [
    {
      name: "strict-transport-security",
      severity: "high",
      title: "Falta cabecera HSTS",
      description:
        "Sin HSTS, el navegador puede conectarse por HTTP aunque el sitio soporte HTTPS.",
      remediation:
        "Agrega: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
      name: "content-security-policy",
      severity: "high",
      title: "Falta Content-Security-Policy",
      description: "Sin CSP, es más fácil explotar vulnerabilidades XSS.",
      remediation: "Agrega: Content-Security-Policy: default-src 'self'",
    },
    {
      name: "x-frame-options",
      severity: "medium",
      title: "Falta X-Frame-Options",
      description:
        "Sin esta cabecera, el sitio puede ser embebido en iframes y sufrir clickjacking.",
      remediation: "Agrega: X-Frame-Options: DENY o SAMEORIGIN",
    },
    {
      name: "x-content-type-options",
      severity: "medium",
      title: "Falta X-Content-Type-Options",
      description:
        "Sin esta cabecera, el navegador puede adivinar el tipo MIME y ejecutar contenido malicioso.",
      remediation: "Agrega: X-Content-Type-Options: nosniff",
    },
    {
      name: "referrer-policy",
      severity: "low",
      title: "Falta Referrer-Policy",
      description:
        "Sin esta cabecera, se puede filtrar la URL de origen a sitios externos.",
      remediation: "Agrega: Referrer-Policy: strict-origin-when-cross-origin",
    },
  ];

  for (const header of requiredHeaders) {
    if (!headers[header.name]) {
      findings.push({
        type: "missing-header",
        severity: header.severity,
        title: header.title,
        description: header.description,
        remediation: header.remediation,
      });
    }
  }

  return findings;
}

function checkServerLeak(headers) {
  const server = headers["server"];
  if (!server) return null;

  const hasVersion = /\d+\.\d+/.test(server);

  if (hasVersion) {
    return {
      type: "info-leak",
      severity: "low",
      title: "El servidor revela su versión",
      description: `La cabecera Server expone: "${server}". Esto ayuda a atacantes a buscar vulnerabilidades específicas.`,
      remediation:
        "Oculta la versión del servidor (nginx: server_tokens off; Apache: ServerTokens Prod).",
    };
  }
  return null;
}

function checkInsecureCookies(headers) {
  const setCookie = headers["set-cookie"];
  if (!setCookie) return [];

  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  const findings = [];

  for (const cookie of cookies) {
    const name = cookie.split("=")[0].trim();
    const lower = cookie.toLowerCase();

    if (!lower.includes("secure")) {
      findings.push({
        type: "insecure-cookie",
        severity: "medium",
        title: `Cookie "${name}" sin flag Secure`,
        description:
          "La cookie puede viajar por HTTP sin cifrar y ser interceptada.",
        remediation: "Agrega el flag Secure a todas las cookies de sesión.",
      });
    }

    if (!lower.includes("httponly")) {
      findings.push({
        type: "insecure-cookie",
        severity: "medium",
        title: `Cookie "${name}" sin flag HttpOnly`,
        description:
          "La cookie es accesible desde JavaScript, facilitando robos por XSS.",
        remediation: "Agrega el flag HttpOnly a todas las cookies de sesión.",
      });
    }
  }

  return findings;
}

module.exports = {
  checkHttps,
  checkSecurityHeaders,
  checkServerLeak,
  checkInsecureCookies,
};
