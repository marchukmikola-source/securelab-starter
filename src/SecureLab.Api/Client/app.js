const listElement = document.querySelector("#incident-list");
const listStatusElement = document.querySelector("#list-status");
const detailsElement = document.querySelector("#incident-details");
const filterForm = document.querySelector("#filter-form");

const summaryStatusElement = document.querySelector("#severity-summary-status");
const summaryListElement = document.querySelector("#severity-summary-list");
const summaryButton = document.querySelector("#load-severity-summary");

async function apiFetch(path, options = {}) {
  const response = await fetch(path, {
    headers: { Accept: "application/json", ...options.headers },
    ...options,
  });

  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new Error(problem?.title ?? `HTTP ${response.status}`);
  }

  return response.json();
}

function createTextElement(tagName, text, className) {
  const element = document.createElement(tagName);
  element.textContent = text;
  if (className) {
    element.className = className;
  }
  return element;
}

function renderIncidentList(incidents) {
  listElement.replaceChildren();

  if (incidents.length === 0) {
    listStatusElement.textContent = "За заданим фільтром інцидентів немає.";
    return;
  }

  listStatusElement.textContent = `Знайдено: ${incidents.length}`;
  for (const incident of incidents) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "incident-card";
    button.append(
      createTextElement("strong", incident.title),
      createTextElement("span", `${incident.severity} · ${incident.status}`, "metadata"),
    );
    button.addEventListener("click", () => loadIncidentDetails(incident.id));
    item.append(button);
    listElement.append(item);
  }
}

function renderIncidentDetails(incident) {
  const heading = createTextElement("h3", incident.title);
  const metadata = createTextElement(
    "p",
    `${incident.severity} · ${incident.status} · автор: ${incident.ownerDisplayName}`,
    "metadata",
  );
  const description = createTextElement("p", incident.description);
  const commentsHeading = createTextElement("h4", "Коментарі");
  const comments = document.createElement("ul");

  for (const comment of incident.comments) {
    const item = document.createElement("li");
    item.append(
      createTextElement("strong", `${comment.authorDisplayName}: `),
      document.createTextNode(comment.text),
    );
    comments.append(item);
  }

  if (incident.comments.length === 0) {
    comments.append(createTextElement("li", "Коментарів немає."));
  }

  detailsElement.className = "";
  detailsElement.replaceChildren(heading, metadata, description, commentsHeading, comments);
}

async function loadIncidents() {
  listStatusElement.textContent = "Завантаження…";
  listElement.replaceChildren();

  const status = new FormData(filterForm).get("status");
  const query = status ? `?status=${encodeURIComponent(status)}` : "";

  try {
    renderIncidentList(await apiFetch(`/api/incidents${query}`));
  } catch (error) {
    listStatusElement.textContent = `Помилка: ${error.message}`;
  }
}

async function loadIncidentDetails(id) {
  detailsElement.className = "details-placeholder";
  detailsElement.textContent = "Завантаження…";

  try {
    renderIncidentDetails(await apiFetch(`/api/incidents/${encodeURIComponent(id)}`));
  } catch (error) {
    detailsElement.textContent = `Помилка: ${error.message}`;
  }
}

// Навчальний probe ЛР 04 викликає цей самий UI-renderer після входу Alice.
// Рішення про доступ залишається на сервері; клієнт лише відображає відповідь.
window.loadIncidentDetails = loadIncidentDetails;

async function loadSeveritySummary() {
  // 1. Стан завантаження (Loading State)
  summaryStatusElement.textContent = "Завантаження…";
  summaryListElement.replaceChildren();

  try {
    // 2. Network request (виклики fetch API через apiFetch)
    const summary = await apiFetch("/api/incidents/severity-summary");

    // 3. Обробка порожнього результату (Empty State)
    if (summary.length === 0) {
      summaryStatusElement.textContent = "Даних немає";
      return;
    }

    summaryStatusElement.textContent = "";
    for (const item of summary) {
      const li = document.createElement("li");
      li.textContent = `${item.severity}: ${item.count}`;
      summaryListElement.append(li);
    }
  } catch (error) {
    // 4. Стан безпечної помилки (Error State) — виводиться зрозуміле повідомлення без витоку стек-трейсу
    summaryStatusElement.textContent = "Не вдалося завантажити підсумок";
  }
}

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loadIncidents();
});

summaryButton.addEventListener("click", loadSeveritySummary);

loadIncidents();
