/* SecureVibe docs — homepage hero animation.
 * Auto-plays the generation-time transcript like a live agent session:
 * typewriters the prompt, then reveals each reasoning step → tool call →
 * code → result in sequence, then loops. Pure DOM/CSS (no GIF), so it
 * stays crisp and theme-aware. Hooks Material's `document$` observable so
 * it survives instant navigation; respects prefers-reduced-motion.
 *
 * Fallback: without JS the transcript renders complete and static (the
 * hidden initial state is gated behind the `.anim` class this script adds).
 */
(function () {
  var REDUCED =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ms before revealing each sequenced element (index matches DOM order:
  // step, tool, step, code, done). First item shows right after typing.
  var GAPS = [0, 850, 650, 800, 900];
  var TYPE_MS = 26;     // per-character typing speed
  var AFTER_TYPE = 450; // pause after the prompt finishes
  var LOOP_HOLD = 3400; // pause on the finished frame before replaying

  function animate() {
    var chat = document.querySelector(".ss-hero .ss-chat");
    if (!chat || chat.dataset.animBound === "1") return;
    chat.dataset.animBound = "1";

    var prompt = chat.querySelector(".ss-chat-prompt");
    var seq = chat.querySelectorAll(
      ".ss-chat-step, .ss-chat-tool, .ss-chat-code, .ss-chat-done"
    );
    var fullText = prompt ? prompt.textContent : "";

    // Reduced motion: leave the complete transcript visible, no animation.
    if (REDUCED) return;

    chat.classList.add("anim");

    var timers = [];
    function later(fn, ms) { timers.push(setTimeout(fn, ms)); }
    function clearAll() { timers.forEach(clearTimeout); timers = []; }
    function gone() {
      if (document.body.contains(chat)) return false;
      clearAll();
      return true;
    }

    function run() {
      if (gone()) return;
      for (var i = 0; i < seq.length; i++) seq[i].classList.remove("is-shown");
      if (prompt) prompt.textContent = "";
      typeAt(0);
    }

    function typeAt(i) {
      if (gone()) return;
      if (!prompt) { reveal(0); return; }
      if (i <= fullText.length) {
        prompt.textContent = fullText.slice(0, i);
        later(function () { typeAt(i + 1); }, TYPE_MS);
      } else {
        later(function () { reveal(0); }, AFTER_TYPE);
      }
    }

    function reveal(n) {
      if (gone()) return;
      if (n >= seq.length) { later(run, LOOP_HOLD); return; } // loop
      seq[n].classList.add("is-shown");
      later(function () { reveal(n + 1); }, GAPS[n + 1] || 800);
    }

    run();
  }

  if (typeof document$ !== "undefined" && document$.subscribe) {
    document$.subscribe(animate); // Material instant navigation
  } else {
    document.addEventListener("DOMContentLoaded", animate);
  }
})();
