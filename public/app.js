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
