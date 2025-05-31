let isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
let currentUser = localStorage.getItem("username") || "";

function initializePage() {
  updateHeader();
  updateSections();
}

function updateHeader() {
  const authButtons = document.getElementById("authButtons");
  const userInfo = document.getElementById("userInfo");
  const welcomeMessage = document.getElementById("welcomeMessage");

  if (isLoggedIn) {
    authButtons.style.display = "none";
    userInfo.style.display = "flex";
    welcomeMessage.textContent = `Welcome, ${currentUser}`;
  } else {
    authButtons.style.display = "flex";
    userInfo.style.display = "none";
  }
}

function updateSections() {
  const encryptContent = document.getElementById("encryptContent");
  const encryptLoginPrompt = document.getElementById("encryptLoginPrompt");
  const decryptContent = document.getElementById("decryptContent");
  const decryptLoginPrompt = document.getElementById("decryptLoginPrompt");
  const checkFilesContent = document.getElementById("checkFilesContent");
  const checkFilesLoginPrompt = document.getElementById(
    "checkFilesLoginPrompt"
  );

  if (isLoggedIn) {
    encryptContent.style.display = "block";
    encryptLoginPrompt.style.display = "none";
    decryptContent.style.display = "block";
    decryptLoginPrompt.style.display = "none";
    checkFilesContent.style.display = "block";
    checkFilesLoginPrompt.style.display = "none";
  } else {
    encryptContent.style.display = "none";
    encryptLoginPrompt.style.display = "block";
    decryptContent.style.display = "none";
    decryptLoginPrompt.style.display = "block";
    checkFilesContent.style.display = "none";
    checkFilesLoginPrompt.style.display = "block";
  }
}

function showSection(sectionId) {
  const sections = document.querySelectorAll(".content-section");
  sections.forEach((section) => {
    section.classList.remove("active");
  });
  const section = document.getElementById(sectionId);
  if (section) {
    section.classList.add("active");
    if (sectionId === "check-files" && isLoggedIn) {
      fetchFileList();
    }
  } else {
    console.error(`Section with ID '${sectionId}' not found.`);
  }
}

function fetchFileList() {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  fetch(`${backendUrl}/api/files`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  })
    .then((response) => {
      if (!response.ok) throw new Error("Failed to fetch file list");
      return response.json();
    })
    .then((data) => {
      const fileListContainer = document.getElementById("fileListContainer");
      fileListContainer.innerHTML = "";
      if (data.files.length === 0) {
        const p = document.createElement("p");
        p.textContent = "No files found.";
        fileListContainer.appendChild(p);
      } else {
        data.files.forEach((file) => {
          const div = document.createElement("div");
          div.className = "file-item";
          const p = document.createElement("p");
          p.textContent = file.name;
          const downloadButton = document.createElement("button");
          downloadButton.textContent = "Download";
          downloadButton.onclick = () => downloadFile(file.name);
          const deleteButton = document.createElement("button");
          deleteButton.textContent = "Delete";
          deleteButton.className = "delete-button";
          deleteButton.onclick = () => deleteFile(file.name);
          div.appendChild(p);
          div.appendChild(downloadButton);
          div.appendChild(deleteButton);
          fileListContainer.appendChild(div);
        });
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      alert("Failed to fetch file list. Please try again.");
    });
}

function downloadFile(filename) {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  fetch(`${backendUrl}/api/download/${encodeURIComponent(filename)}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`,
    },
  })
    .then((response) => {
      if (!response.ok) throw new Error("Failed to download file");
      return response.blob();
    })
    .then((blob) => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      alert(`File ${filename} downloaded successfully!`);
    })
    .catch((error) => {
      console.error("Error:", error);
      alert("Failed to download file. Please try again.");
    });
}

function deleteFile(filename) {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  if (confirm(`Are you sure you want to delete the file "${filename}"?`)) {
    fetch(`${backendUrl}/api/delete/${encodeURIComponent(filename)}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${localStorage.getItem("token")}`,
      },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Failed to delete file");
        alert(`File ${filename} deleted successfully!`);
        fetchFileList(); // 刷新檔案列表
      })
      .catch((error) => {
        console.error("Error:", error);
        alert("Failed to delete file. Please try again.");
      });
  }
}

function logout() {
  if (confirm("Are you sure you want to logout?")) {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("username");
    localStorage.removeItem("token");
    isLoggedIn = false;
    currentUser = "";
    updateHeader();
    updateSections();
    showSection("login");
    alert("Logged out successfully!");
  }
}

// Encrypt Section Logic
const dropArea = document.getElementById("dropArea");
const fileList = document.getElementById("fileList");
const uploadButton = document.getElementById("uploadButton");
const algorithmSelect = document.getElementById("algorithmSelect");
let filesToUpload = [];

dropArea.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropArea.classList.add("dragover");
});

dropArea.addEventListener("dragleave", () => {
  dropArea.classList.remove("dragover");
});

dropArea.addEventListener("drop", (e) => {
  e.preventDefault();
  dropArea.classList.remove("dragover");
  const files = e.dataTransfer.files;
  handleFiles(files, fileList, uploadButton, "encrypt");
});

function handleFiles(files, fileListElement, buttonElement, section) {
  const filesArray = Array.from(files);
  fileListElement.innerHTML = "";
  filesArray.forEach((file) => {
    const p = document.createElement("p");
    p.textContent = file.name;
    fileListElement.appendChild(p);
  });
  if (filesArray.length > 0) {
    buttonElement.style.display = "block";
  }
  if (section === "encrypt") {
    filesToUpload = filesArray;
  } else if (section === "decrypt") {
    decryptFilesToUpload = filesArray;
  }
}

uploadButton.addEventListener("click", () => {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  if (confirm("Are you sure you want to encrypt these files?")) {
    const selectedAlgorithm = algorithmSelect.value;
    const formData = new FormData();
    formData.append("algorithm", selectedAlgorithm);
    filesToUpload.forEach((file) => {
      formData.append("files", file);
    });

    fetch(`${backendUrl}/api/encrypt`, {
      method: "POST",
      body: formData,
      headers: {
        Authorization: `Bearer ${localStorage.getItem("token")}`,
      },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Encryption failed");
        alert(`Files encrypted successfully using ${selectedAlgorithm}!`);
        fileList.innerHTML = "";
        uploadButton.style.display = "none";
        filesToUpload = [];
      })
      .catch((error) => {
        console.error("Error:", error);
        alert("Encryption failed. Please try again.");
      });
  }
});

// Decrypt Section Logic
const decryptDropArea = document.getElementById("decryptDropArea");
const decryptFileList = document.getElementById("decryptFileList");
const decryptButton = document.getElementById("decryptButton");
let decryptFilesToUpload = [];

decryptDropArea.addEventListener("dragover", (e) => {
  e.preventDefault();
  decryptDropArea.classList.add("dragover");
});

decryptDropArea.addEventListener("dragleave", () => {
  decryptDropArea.classList.remove("dragover");
});

decryptDropArea.addEventListener("drop", (e) => {
  e.preventDefault();
  decryptDropArea.classList.remove("dragover");
  const files = e.dataTransfer.files;
  handleFiles(files, decryptFileList, decryptButton, "decrypt");
});

decryptButton.addEventListener("click", () => {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  if (confirm("Are you sure you want to decrypt these files?")) {
    const formData = new FormData();
    decryptFilesToUpload.forEach((file) => {
      formData.append("files", file);
    });

    fetch(`${backendUrl}/api/decrypt`, {
      method: "POST",
      body: formData,
      headers: {
        Authorization: `Bearer ${localStorage.getItem("token")}`,
      },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Decryption failed");
        alert("Files decrypted successfully!");
        decryptFileList.innerHTML = "";
        decryptButton.style.display = "none";
        decryptFilesToUpload = [];
      })
      .catch((error) => {
        console.error("Error:", error);
        alert("Decryption failed. Please try again.");
      });
  }
});

// Login Form Logic
document
  .getElementById("loginForm")
  .addEventListener("submit", async function (event) {
    event.preventDefault();
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;
    const otp = document.getElementById("login-otp").value;
    const loginError = document.getElementById("login-error");

    try {
      const response = await fetch(`${backendUrl}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password, otp }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Login failed");
      }

      localStorage.setItem("token", data.token);
      localStorage.setItem("isLoggedIn", "true");
      localStorage.setItem("username", username);
      isLoggedIn = true;
      currentUser = username;

      alert("Login successful!");
      loginError.textContent = "";
      updateHeader();
      updateSections();
      showSection("home");
    } catch (error) {
      loginError.textContent = error.message;
      console.error("Error:", error);
    }
  });

// Register Form Logic
const registerForm = document.getElementById("registerForm");
const registerSubmit = document.getElementById("register-submit");
const registerPasswordError = document.getElementById(
  "register-password-error"
);
const registerError = document.getElementById("register-error");
const qrCodeDiv = document.getElementById("qr-code");
const qrCodeImg = document.getElementById("qr-code-img");
const registerInputs = registerForm.querySelectorAll("input");

registerInputs.forEach((input) => {
  input.addEventListener("input", validateRegisterForm);
});

function validateRegisterForm() {
  const email = document.getElementById("register-email").value;
  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;
  const confirmPassword = document.getElementById(
    "register-confirm-password"
  ).value;

  let errorMessage = "";

  if (!email || !username || !password || !confirmPassword) {
    errorMessage = "All fields are required!";
  } else if (password !== confirmPassword) {
    errorMessage = "Password and confirm password do not match!";
  }

  if (errorMessage) {
    registerPasswordError.textContent = errorMessage;
    registerPasswordError.style.display = "block";
    registerSubmit.disabled = true;
  } else {
    registerPasswordError.style.display = "none";
    registerSubmit.disabled = false;
  }
}

registerForm.addEventListener("submit", async function (event) {
  event.preventDefault();
  const email = document.getElementById("register-email").value;
  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;

  try {
    const response = await fetch(`${backendUrl}/api/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, username, password }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Registration failed");
    }

    qrCodeImg.src = data.qrCodeUrl;
    qrCodeDiv.style.display = "block";
    alert(
      "Registration successful! Please scan the QR code with Google Authenticator, then login."
    );
    registerError.textContent = "";
  } catch (error) {
    registerError.textContent = error.message;
    qrCodeDiv.style.display = "none";
    console.error("Error:", error);
  }
});

// 初始化頁面
initializePage();
