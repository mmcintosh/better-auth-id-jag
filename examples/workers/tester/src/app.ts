// The tester's one script (/app.js): copy buttons. Any button with data-copy puts that text on the clipboard.
export const APP_JS = `document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest("button[data-copy]");
  if (!b) return;
  navigator.clipboard.writeText(b.getAttribute("data-copy")).then(function () {
    var t = b.textContent;
    b.textContent = "Copied";
    setTimeout(function () { b.textContent = t; }, 1500);
  });
});
`;
