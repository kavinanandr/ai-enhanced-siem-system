// Incident History page: auto-submit the filter form when a dropdown
// changes, so severity/attack-type/sort filtering feels instant without
// requiring the user to click "Go" every time.
(function () {
  const form = document.querySelector('form[action*="incidents"]');
  if (!form) return;

  form.querySelectorAll('select[name="severity"], select[name="attack_type"], select[name="sort"]')
    .forEach((el) => el.addEventListener("change", () => form.submit()));
})();
