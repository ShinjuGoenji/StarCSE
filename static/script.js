const backendUrl = "https://starcse.onrender.com";
// const backendUrl = 'https://d18d-140-113-212-14.ngrok-free.app/'

// 檢查登入狀態
let isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
let currentUser = localStorage.getItem("username") || "";

// 初始化頁面
function initializePage() {
  updateHeader();
  updateSections();
}

// 更新右上角顯示
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

// 控制 Encrypt 和 Decrypt 區塊的顯示
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

// 切換頁面
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

// 獲取加密檔案清單
function fetchFileList() {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  fetch(`${backendUrl}/api/files`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ currentUser }),
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
          downloadButton.onclick = () => downloadFile(file.id); // Update to use file ID for download

          const deleteButton = document.createElement("button");
          deleteButton.textContent = "Delete";
          deleteButton.className = "delete-button";
          deleteButton.onclick = () => deleteFile(file.id); // Update to use file ID for deletion

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

// Function to download the file
function downloadFile(fileId) {
  fetch(`${backendUrl}/api/files/${fileId}/download`, {
    method: "GET",
  })
    .then((response) => {
      if (!response.ok) {
        const errorData = response.json();
        throw new Error(errorData.detail || "Failed to download file");
      }
      return response.blob();
    })
    .then((blob) => {
      // Create a link element to trigger the download
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `file_${fileId}`; // Or use the file's original name
      a.click();
    })
    .catch((error) => {
      console.error("Error:", error);
      alert("Failed to download file. Please try again.");
    });
}

// Function to delete the file
function deleteFile(fileId) {
  if (!confirm("Are you sure you want to delete this file?")) {
    return;
  }

  fetch(`${backendUrl}/api/files/${fileId}/delete`, {
    method: "DELETE",
  })
    .then((response) => {
      if (!response.ok) {
        const errorData = response.json();
        throw new Error(errorData.detail || "Failed to delete file");
      }
      alert("File deleted successfully!");
      fetchFileList(); // Refresh the file list after deletion
    })
    .catch((error) => {
      console.error("Error:", error);
      alert("Failed to delete file. Please try again.");
    });
}

// 登出功能
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
const encryptButton = document.getElementById("encryptButton");
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
  handleFiles(files, fileList, encryptButton, uploadButton, "encrypt");
});

function handleFiles(
  files,
  fileListElement,
  buttonElement1,
  buttonElement2,
  section
) {
  const filesArray = Array.from(files);
  fileListElement.innerHTML = "";
  filesArray.forEach((file) => {
    const p = document.createElement("p");
    p.textContent = file.name;
    fileListElement.appendChild(p);
  });
  if (filesArray.length > 0) {
    buttonElement1.style.display = "block";
    buttonElement2.style.display = "block";
  }
  if (section === "encrypt") {
    filesToUpload = filesArray;
  } else if (section === "decrypt") {
    decryptFilesToUpload = filesArray;
  }
}

encryptButton.addEventListener("click", () => {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  if (confirm("Are you sure you want to encrypt these files?")) {
    const formData = new FormData();

    filesToUpload.forEach((file) => {
      formData.append("files", file);
    });

    formData.append("username", currentUser);
    formData.append("isUpload", false);
    formData.append("recipients", JSON.stringify(addedUsers));
    fetch(`${backendUrl}/api/encrypt`, {
      method: "POST",
      body: formData,
    })
      .then((response) => {
        if (!response.ok) throw new Error("Encryption failed");
        return response.blob(); // ZIP file
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "encrypted_package.zip";
        link.click();
        URL.revokeObjectURL(url);
        alert("Files encrypted and downloaded successfully!");
        fileList.innerHTML = "";
        encryptButton.style.display = "none";
        uploadButton.style.display = "none";
        filesToUpload = [];
      })
      .catch((error) => {
        console.error("Error:", error);
        alert("Encryption failed. Please try again.");
      });
  }
});

uploadButton.addEventListener("click", () => {
  if (!isLoggedIn) {
    alert("Please login first!");
    showSection("login");
    return;
  }

  if (confirm("Are you sure you want to encrypt these files?")) {
    const formData = new FormData();

    filesToUpload.forEach((file) => {
      formData.append("files", file);
    });

    formData.append("username", currentUser);
    formData.append("isUpload", true);
    formData.append("recipients", JSON.stringify(addedUsers));
    fetch(`${backendUrl}/api/encrypt`, {
      method: "POST",
      body: formData,
    })
      .then((response) => {
        if (!response.ok) throw new Error("Encryption failed");
        alert("Files encrypted and uploaded successfully!");
        fileList.innerHTML = "";
        encryptButton.style.display = "none";
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

  if (decryptFilesToUpload.length !== 1) {
    alert(`請上傳一個要解密的檔案。 len=${decryptFilesToUpload.length}`);
    return;
  }

  if (confirm("Are you sure you want to decrypt this file?")) {
    const formData = new FormData();
    formData.append("file", decryptFilesToUpload[0]);
    formData.append("username", currentUser);

    fetch(`${backendUrl}/api/decrypt`, {
      method: "POST",
      body: formData,
    })
      .then(async (response) => {
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.detail);
        }
        return response.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "decrypted_file.zip";
        link.click();
        URL.revokeObjectURL(url);
        alert("File decrypted and downloaded successfully!");
        decryptFileList.innerHTML = "";
        decryptButton.style.display = "none";
        decryptFilesToUpload = [];
      })
      .catch((error) => {
        console.error("Error:", error);
        alert("解密失敗：" + error.message);
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

let allUsers = [];

// 頁面載入時取得所有使用者
async function fetchUserList() {
  try {
    const response = await fetch(`${backendUrl}/api/users`);
    if (!response.ok) throw new Error("取得使用者清單失敗");
    allUsers = await response.json(); // ["user1", "user2", ...]
  } catch (error) {
    console.error("Error fetching user list:", error);
  }
}

// 顯示符合搜尋條件的提示名單
function showUserSuggestions(query) {
  const suggestionBox = document.getElementById("userSuggestions");
  suggestionBox.innerHTML = "";

  if (!query) {
    suggestionBox.style.display = "none";
    return;
  }

  const suggestions = allUsers.filter((user) =>
    user.toLowerCase().includes(query.toLowerCase())
  );

  if (suggestions.length === 0) {
    suggestionBox.style.display = "none";
    return;
  }

  suggestions.forEach((user) => {
    const li = document.createElement("li");
    li.textContent = user;
    li.style.padding = "5px";
    li.style.cursor = "pointer";

    li.addEventListener("click", () => {
      document.getElementById("userSearchInput").value = user;
      suggestionBox.style.display = "none";
    });

    li.addEventListener("mouseenter", () => {
      li.style.backgroundColor = "#ddd";
    });

    li.addEventListener("mouseleave", () => {
      li.style.backgroundColor = "white";
    });

    suggestionBox.appendChild(li);
  });

  suggestionBox.style.display = "block";
}

// 綁定 input 輸入事件
document.getElementById("userSearchInput").addEventListener("input", (e) => {
  showUserSuggestions(e.target.value);
});

// 存放已加入的使用者列表
const addedUsers = [];

function addUser() {
  const input = document.getElementById("userSearchInput");
  const username = input.value.trim();

  if (username && !addedUsers.includes(username)) {
    addedUsers.push(username);
    updateAddedUsersList();
    input.value = ""; // 清空輸入框
  }
}

function updateAddedUsersList() {
  const list = document.getElementById("addedUsers");
  list.innerHTML = ""; // 清空現有列表

  addedUsers.forEach((user, index) => {
    const li = document.createElement("li");
    li.textContent = user;

    // 加入刪除按鈕
    const removeBtn = document.createElement("span");
    removeBtn.textContent = " ×";
    removeBtn.className = "remove-user";
    removeBtn.style.cursor = "pointer";
    removeBtn.style.color = "red";
    removeBtn.style.marginLeft = "8px";
    removeBtn.setAttribute("data-index", index);

    li.appendChild(removeBtn);
    list.appendChild(li);
  });
}

document.getElementById("addedUsers").addEventListener("click", function (e) {
  if (e.target.classList.contains("remove-user")) {
    const index = parseInt(e.target.getAttribute("data-index"), 10);
    if (!isNaN(index)) {
      addedUsers.splice(index, 1); // 從陣列中移除
      updateAddedUsersList(); // 重新渲染畫面
    }
  }
});

// 初始化取得使用者清單
fetchUserList();

// 初始化頁面
initializePage();
