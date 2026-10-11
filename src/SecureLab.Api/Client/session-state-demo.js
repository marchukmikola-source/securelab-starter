import { apiFetch } from "./api-fetch.js";

const state = document.querySelector("#session-state");
const message = document.querySelector("#message");

function showState(value) {
  state.textContent = {
    anonymous: "Не ввійшли",
    "signed-in": "Сеанс активний",
    unknown: "Стан сеансу невизначений"
  }[value];
}

async function refreshSessionState() {
  try {
    const response = await apiFetch("/api/auth/session-check");

    if (response.status === 204) {
      showState("signed-in");
      message.textContent = "";
    } else if (response.status === 401) {
      showState("anonymous");
      message.textContent = "";
    } else {
      showState("unknown");
      message.textContent = `Перевірка сеансу: ${response.status}.`;
    }
  } catch {
    showState("unknown");
    message.textContent = "Не вдалося перевірити стан сеансу.";
  }
}

document.querySelector("#refresh").addEventListener("click", () => {
  void refreshSessionState();
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    const response = await apiFetch("/api/auth/logout", { method: "POST" });

    if (response.status !== 204) {
      showState("unknown");
      message.textContent = `Вихід не виконано: ${response.status}.`;
      return;
    }

    await refreshSessionState();
  } catch {
    showState("unknown");
    message.textContent = "Не вдалося виконати вихід.";
  }
});

void refreshSessionState();
