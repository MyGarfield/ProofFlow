const ProofFlowStoryboard = (() => {
  "use strict";

  function formatClock(value) {
    const seconds = Math.max(0, Math.min(90, Math.round(Number(value) || 0)));
    return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(
      seconds % 60,
    ).padStart(2, "0")}`;
  }

  function selectSegment(segments, value) {
    if (!Array.isArray(segments) || segments.length === 0) {
      return null;
    }
    const time = Math.max(0, Math.min(90, Number(value) || 0));
    return (
      segments.find((segment) => time >= segment.start && time < segment.end) ||
      segments[segments.length - 1]
    );
  }

  function hasHorizontalOverflow(documentElement) {
    return documentElement.scrollWidth > documentElement.clientWidth;
  }

  return Object.freeze({ formatClock, hasHorizontalOverflow, selectSegment });
})();

if (typeof module === "object" && module.exports) {
  module.exports = ProofFlowStoryboard;
}

if (typeof document !== "undefined") {
  (() => {
    "use strict";

    const slider = document.querySelector("#story-scrubber");
    const time = document.querySelector("#story-time");
    const step = document.querySelector("#story-step");
    const heading = document.querySelector("#story-heading");
    const caption = document.querySelector("#story-caption");
    const transcriptItems = Array.from(
      document.querySelectorAll("#storyboard-transcript [data-start][data-end]"),
    );
    const segments = transcriptItems.map((item) => ({
      caption: item.querySelector("span").textContent.trim(),
      element: item,
      end: Number(item.dataset.end),
      heading: item.dataset.heading,
      start: Number(item.dataset.start),
      step: item.dataset.step,
    }));

    function renderStoryboard(value) {
      const segment = ProofFlowStoryboard.selectSegment(segments, value);
      if (!segment) {
        return;
      }
      const clock = ProofFlowStoryboard.formatClock(value);
      time.textContent = `${clock} / 01:30`;
      step.textContent = segment.step;
      heading.textContent = segment.heading;
      caption.textContent = segment.caption;
      slider.setAttribute("aria-valuetext", `${clock}，${segment.heading}`);
      transcriptItems.forEach((item) => {
        const current = item === segment.element;
        item.classList.toggle("is-current", current);
        if (current) {
          item.setAttribute("aria-current", "true");
        } else {
          item.removeAttribute("aria-current");
        }
      });
    }

    function recordLayoutState() {
      document.documentElement.dataset.horizontalOverflow = String(
        ProofFlowStoryboard.hasHorizontalOverflow(document.documentElement),
      );
    }

    slider.addEventListener("input", (event) => renderStoryboard(event.currentTarget.value));
    window.addEventListener("resize", recordLayoutState, { passive: true });
    window.addEventListener("load", recordLayoutState, { once: true });

    renderStoryboard(slider.value);
    requestAnimationFrame(recordLayoutState);
  })();
}
