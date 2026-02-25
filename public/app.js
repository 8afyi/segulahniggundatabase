(function attachDeleteConfirm() {
  const forms = document.querySelectorAll("form[data-confirm]");
  for (const form of forms) {
    form.addEventListener("submit", (event) => {
      const message = form.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  }
})();

(function attachRowAudioPreview() {
  const previewButtons = document.querySelectorAll("[data-audio-button]");
  if (previewButtons.length === 0) {
    return;
  }

  let activePreview = null;

  function updateButtonState(button, isPlaying) {
    const playLabel = button.getAttribute("data-play-label") || "Play";
    const pauseLabel = button.getAttribute("data-pause-label") || "Pause";
    button.textContent = isPlaying ? pauseLabel : playLabel;
    button.setAttribute("aria-pressed", isPlaying ? "true" : "false");
  }

  function stopActivePreview() {
    if (!activePreview) {
      return;
    }

    activePreview.player.pause();
    activePreview.player.currentTime = 0;
    updateButtonState(activePreview.button, false);
    activePreview = null;
  }

  for (const button of previewButtons) {
    const row = button.closest("tr");
    if (!row) {
      continue;
    }

    const player = row.querySelector("[data-audio-player]");
    if (!player) {
      continue;
    }

    updateButtonState(button, false);

    button.addEventListener("click", () => {
      if (activePreview && activePreview.player !== player) {
        stopActivePreview();
      }

      if (!player.paused) {
        stopActivePreview();
        return;
      }

      const playPromise = player.play();
      if (playPromise && typeof playPromise.catch === "function") {
        playPromise.catch(() => {
          updateButtonState(button, false);
          if (activePreview && activePreview.player === player) {
            activePreview = null;
          }
        });
      }

      updateButtonState(button, true);
      activePreview = { button, player };
    });

    player.addEventListener("ended", () => {
      if (activePreview && activePreview.player === player) {
        updateButtonState(button, false);
        activePreview = null;
      }
    });

    player.addEventListener("pause", () => {
      if (activePreview && activePreview.player === player && !player.ended) {
        updateButtonState(button, false);
        activePreview = null;
      }
    });
  }
})();
