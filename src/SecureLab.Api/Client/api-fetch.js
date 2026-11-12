const tokenPath = "/api/auth/csrf";
const tokenHeader = "X-CSRF-TOKEN";
let requestToken = null;
let pendingToken = null;

function clearToken() {
  requestToken = null;
  pendingToken = null;
}

async function ensureToken() {
  if (requestToken) return requestToken;
  if (!pendingToken) {
    pendingToken = (async () => {
      const response = await fetch(tokenPath, { credentials: "same-origin", cache: "no-store" });
      if (response.status === 401) return null;
      if (!response.ok) throw new Error("Не вдалося підготувати захищений запит.");
      const data = await response.json();
      if (data.headerName !== tokenHeader || typeof data.requestToken !== "string" || !data.requestToken) {
        throw new Error("Неочікуваний формат CSRF-токена.");
      }
      requestToken = data.requestToken;
      return requestToken;
    })();
  }
  try { return await pendingToken; }
  finally { pendingToken = null; }
}

export async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);

  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }

  const method = String(options.method ?? "GET").toUpperCase();
  const isLogin = url.pathname === "/api/auth/login" && method === "POST";
  const isLogout = url.pathname === "/api/auth/logout" && method === "POST";
  const isRevokeAll = url.pathname === "/api/me/sessions/revoke-all" && method === "POST";
  const isPublicAuth = isLogin || (url.pathname === "/api/auth/register" && method === "POST");
  const headers = new Headers(options.headers);
  if (isLogin) clearToken();
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && !isPublicAuth) {
    const token = await ensureToken();
    // An anonymous request still reaches the normal authentication boundary (401).
    if (token) headers.set(tokenHeader, token);
  }
  const response = await fetch(url, { ...options, method, headers, credentials: "same-origin" });
  if (response.status === 401 || (response.ok && (isLogin || isLogout || isRevokeAll))) clearToken();
  if (response.ok && isLogin) await ensureToken();
  if (response.status === 400) {
    const problem = await response.clone().json().catch(() => null);
    if (problem?.code === "csrf_validation_failed") clearToken();
  }
  // A failed mutation is never replayed automatically.
  return response;
}
