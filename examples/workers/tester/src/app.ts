// The tester's one script (/app.js): copy buttons. Any button with data-copy puts that text on the clipboard.
// The copy command on a hidden textarea goes first: it runs inside the click, so it works where the asynchronous
// clipboard API is blocked or waiting on a permission. The clipboard API is the fallback; if both fail, the button
// says so instead of doing nothing.
export const APP_JS = `document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest("button[data-copy]");
  if (!b) return;
  var text = b.getAttribute("data-copy");
  var label = b.getAttribute("data-label") || b.textContent;
  b.setAttribute("data-label", label);
  function show(ok) {
    b.textContent = ok ? "Copied" : "Couldn't copy: select it instead";
    setTimeout(function () { b.textContent = label; }, 2000);
  }
  var t = document.createElement("textarea");
  t.value = text;
  t.setAttribute("readonly", "");
  t.style.position = "fixed";
  t.style.top = "0";
  t.style.opacity = "0";
  document.body.appendChild(t);
  t.select();
  var ok = false;
  try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
  document.body.removeChild(t);
  if (ok) return show(true);
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { show(true); }, function () { show(false); });
  else show(false);
});
`;

/**
 * The script's address, with a hash of its content: a changed script gets a new address, so browsers never keep an
 * old one from their cache. Computed without I/O or randomness, so it may run while the module loads.
 */
export const APP_JS_URL = `/app.js?v=${[...APP_JS].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) >>> 0, 7).toString(36)}`;
