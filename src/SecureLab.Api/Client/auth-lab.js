import { apiFetch } from "./api-fetch.js";

const sessionState = document.querySelector("#session-state");
const message = document.querySelector("#message");
const profile = document.querySelector("#profile");
const incidentResult = document.querySelector("#incident-result");
const registerForm = document.querySelector("#register-form");
const loginForm = document.querySelector("#login-form");
const incidentForm = document.querySelector("#incident-form");

function showSessionState(state) {
  sessionState.textContent = {
    anonymous: "Не ввійшли",
    "signed-in": "Сеанс активний",
    unknown: "Стан сеансу невизначений"
  }[state];
}

function showMessage(text = "") {
  message.textContent = text;
}

function clearProfile() {
  profile.replaceChildren();
}

function showProfile(currentUser) {
  clearProfile();

  for (const [label, value] of [
    ["ID", currentUser.id],
    ["Ім’я користувача", currentUser.userName],
    ["Ім’я профілю", currentUser.displayName]
  ]) {
    const term = document.createElement("dt");
    term.textContent = label;
    const definition = document.createElement("dd");
    definition.textContent = value;
    profile.append(term, definition);
  }
}

async function readJson(response) {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Сервер повернув неочікуваний формат відповіді.");
  }

  return response.json();
}

async function loadProfile() {
  const response = await apiFetch("/api/me");

  if (response.status === 401) {
    clearProfile();
    showSessionState("anonymous");
    return false;
  }

  if (!response.ok) {
    clearProfile();
    showMessage(`Не вдалося отримати профіль: ${response.status}.`);
    return false;
  }

  const currentUser = await readJson(response);
  showProfile(currentUser);
  showSessionState("signed-in");
  return true;
}

async function refreshSessionState() {
  try {
    const response = await apiFetch("/api/auth/session-check");

    if (response.status === 204) {
      showSessionState("signed-in");
      await loadProfile();
      return;
    }

    if (response.status === 401) {
      clearProfile();
      showSessionState("anonymous");
      return;
    }

    clearProfile();
    showSessionState("unknown");
    showMessage(`Перевірка сеансу: ${response.status}.`);
  } catch {
    clearProfile();
    showSessionState("unknown");
    showMessage("Не вдалося перевірити стан сеансу.");
  }
}

registerForm.addEventListener("submit", async event => {
  event.preventDefault();
  const formData = new FormData(registerForm);
  const passwordInput = registerForm.elements.password;

  try {
    const response = await apiFetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userName: formData.get("userName"),
        email: formData.get("email"),
        displayName: formData.get("displayName"),
        password: formData.get("password")
      })
    });

    if (response.status === 201) {
      registerForm.reset();
      showMessage("Реєстрацію завершено. Тепер увійдіть у систему.");
      return;
    }

    showMessage(`Реєстрацію не завершено: ${response.status}.`);
  } catch {
    showMessage("Не вдалося виконати реєстрацію.");
  } finally {
    passwordInput.value = "";
  }
});

loginForm.addEventListener("submit", async event => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  const passwordInput = loginForm.elements.password;

  try {
    const response = await apiFetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userName: formData.get("userName"),
        password: formData.get("password")
      })
    });

    if (response.status === 204) {
      loginForm.reset();
      showMessage("Вхід виконано.");
      await refreshSessionState();
      return;
    }

    showMessage(`Вхід не виконано: ${response.status}.`);
  } catch {
    showMessage("Не вдалося виконати вхід.");
  } finally {
    passwordInput.value = "";
  }
});

document.querySelector("#refresh-profile").addEventListener("click", async () => {
  try {
    await loadProfile();
  } catch {
    clearProfile();
    showMessage("Не вдалося отримати профіль.");
  }
});

incidentForm.addEventListener("submit", async event => {
  event.preventDefault();
  const formData = new FormData(incidentForm);
  const occurredAt = new Date(String(formData.get("occurredAtUtc")));

  if (Number.isNaN(occurredAt.valueOf())) {
    incidentResult.textContent = "Укажіть коректний час події.";
    return;
  }

  try {
    const response = await apiFetch("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: formData.get("title"),
        description: formData.get("description"),
        severity: formData.get("severity"),
        occurredAtUtc: occurredAt.toISOString()
      })
    });

    if (response.status === 401) {
      clearProfile();
      showSessionState("anonymous");
      incidentResult.textContent = "Для створення інциденту потрібно ввійти.";
      return;
    }

    if (!response.ok) {
      incidentResult.textContent = `Інцидент не створено: ${response.status}.`;
      return;
    }

    const incident = await readJson(response);
    incidentResult.textContent = `Інцидент створено: ${incident.title}.`;
    incidentForm.reset();
  } catch {
    incidentResult.textContent = "Не вдалося створити інцидент.";
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    const response = await apiFetch("/api/auth/logout", { method: "POST" });

    if (response.status !== 204) {
      showMessage(`Вихід не виконано: ${response.status}.`);
      return;
    }

    clearProfile();
    incidentResult.textContent = "";
    incidentForm.reset();
    showMessage("Вихід виконано.");
    await loadProfile();
  } catch {
    showMessage("Не вдалося виконати вихід.");
  }
});

void refreshSessionState();
