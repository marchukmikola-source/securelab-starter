await (async () => {
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };

  const id = document.querySelector("#incident-id").value.trim();
  check(id.length > 0, "Enter an incident Guid with public comments");

  const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
  check(response.status === 200, `Unexpected HTTP ${response.status}`);
  const data = await response.json();
  check(Array.isArray(data.comments), "Details response has no comments array");
  check(data.comments.length > 0, "Choose a fixture with at least one public comment");

  const assertRenderedComments = () => {
    const rendered = [...document.querySelector("#comments").children];
    check(rendered.length === data.comments.length, "Wrong rendered comment count");

    data.comments.forEach((comment, index) => {
      const paragraph = rendered[index];
      check(paragraph.tagName === "P", `Comment ${index} is not a paragraph`);
      check(
        paragraph.textContent === comment.text,
        `Comment ${index} text changed`,
      );
      check(
        paragraph.childElementCount === 0,
        `Comment ${index} became HTML elements`,
      );
    });
  };

  await load();
  assertRenderedComments();

  await load();
  assertRenderedComments();

  await new Promise((resolve) => setTimeout(resolve, 500));
  check(
    document.querySelector("#lab05-marker-target")
      .getAttribute("data-lab05-marker") === null,
    "Marker executed",
  );

  console.log("PASS: every persisted comment rendered as plain text twice");
})();
