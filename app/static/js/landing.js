/* Landing page motion: reveal sections as they scroll into view and draw the highlighter strokes.
   Only for visitors who allow motion, and only for what starts below the fold, so content that is
   already on screen never disappears and reappears. Without this script everything is simply shown. */
(function () {
  "use strict";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce || !("IntersectionObserver" in window)) return;
  document.documentElement.classList.add("js-motion");

  function below(el) { return el.getBoundingClientRect().top >= window.innerHeight; }

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting) return;
      var el = e.target;
      if (el.classList.contains("l-mark")) el.classList.add("is-drawn");
      else { el.classList.remove("is-pending"); el.classList.add("is-in"); }
      io.unobserve(el);
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.12 });

  function start() {
    document.querySelectorAll("[data-reveal]").forEach(function (el) {
      if (below(el)) el.classList.add("is-pending");
      else if (el.matches('[data-reveal="draw"]')) el.classList.add("is-in");
      io.observe(el);
    });
    document.querySelectorAll(".l-mark").forEach(function (m) { io.observe(m); });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
