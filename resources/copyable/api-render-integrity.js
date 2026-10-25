await (async () => {
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };

  const id = document.querySelector("#incident-id").value.trim();
  check(id.length > 0, "Enter the fixture Guid");

  const details = async () => {
    const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
    check(response.status === 200, `Unexpected HTTP ${response.status}`);
    return response.json();
  };

  const before = await details();
  await load();
  const after = await details();

  const description = document.querySelector("#description");
  check(before.description === after.description, "API description changed after render");
  check(description.textContent === before.description, "Rendered text differs from API");
  check(description.childElementCount === 0, "Description became HTML elements");

  console.log({
    apiValueStable: true,
    renderedValueMatchesApi: true,
    descriptionChildElements: description.childElementCount,
  });
})();
