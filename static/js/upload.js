// Upload page: drag-and-drop + selected-file preview for the dropzone.
(function () {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const fileNameDisplay = document.getElementById("fileNameDisplay");

  if (!dropzone || !fileInput) return;

  function showFileName(file) {
    if (file) {
      fileNameDisplay.textContent = `Selected: ${file.name}`;
    }
  }

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) showFileName(fileInput.files[0]);
  });

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length) {
      fileInput.files = dt.files;
      showFileName(dt.files[0]);
    }
  });
})();
