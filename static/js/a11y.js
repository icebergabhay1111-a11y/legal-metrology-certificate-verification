/* Text size and high contrast (GIGW accessibility tools).
   The page works fully without this file; the buttons only appear when it runs. */
(function () {
  var root = document.documentElement;
  var tools = document.getElementById("a11y-tools");
  if (!tools) { return; }

  // Remember the visitor's choice on this browser only. Storage can fail
  // (private mode, blocked cookies) - then the choice lasts for this page.
  function save(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
  }
  function load(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }

  // Apply a text size: "sm", "" (normal), "lg" or "xl".
  function setSize(size) {
    root.classList.remove("fs-sm", "fs-lg", "fs-xl");
    if (size) { root.classList.add("fs-" + size); }
    save("fs", size);
  }

  // Turn high contrast on or off and tell screen readers the new state.
  function setContrast(on) {
    root.classList.toggle("hc", on);
    document.getElementById("hc").setAttribute("aria-pressed", on ? "true" : "false");
    save("hc", on ? "1" : "");
  }

  var buttons = tools.querySelectorAll("[data-fs]");
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener("click", function () { setSize(this.getAttribute("data-fs")); });
  }
  document.getElementById("hc").addEventListener("click", function () {
    setContrast(!root.classList.contains("hc"));
  });

  // Print buttons are hidden until this script runs, since they need it.
  var printers = document.querySelectorAll("[data-print]");
  for (var j = 0; j < printers.length; j++) {
    printers[j].hidden = false;
    printers[j].addEventListener("click", function () { window.print(); });
  }

  setSize(load("fs") || "");
  setContrast(load("hc") === "1");
  tools.hidden = false;
})();
