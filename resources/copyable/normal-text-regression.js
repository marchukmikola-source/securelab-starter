await (async () => {
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };

  const title = "O'Brien — «тест» < > Українська";
  const prefix =
    "O'Brien — \"подвійні лапки\"; </> < >; Українська: ї, є, ґ. ";
  const description = prefix + "x".repeat(4000 - prefix.length);

  const response = await fetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      title,
      description,
      severity: "Low",
      occurredAtUtc: new Date().toISOString(),
    }),
  });
  check(response.status === 201, `Unexpected POST ${response.status}`);

  const created = await response.json();
  document.querySelector("#incident-id").value = created.id;
  await load();

  const descriptionBox = document.querySelector("#description");
  check(document.querySelector("#title").textContent === title, "Title changed");
  check(descriptionBox.textContent === description, "Description changed");
  check(descriptionBox.textContent.length === 4000, "Wrong description length");
  check(descriptionBox.childElementCount === 0, "Description became HTML");
  check(
    document.querySelector("#lab05-marker-target")
      .getAttribute("data-lab05-marker") === null,
    "Marker executed",
  );

  console.log({
    post: response.status,
    titlePreserved: true,
    descriptionPreserved: true,
    descriptionLength: descriptionBox.textContent.length,
    childElements: descriptionBox.childElementCount,
    marker: null,
  });
})();
