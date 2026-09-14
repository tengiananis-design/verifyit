```javascript
/* =========================================================
   VERIFYIT V1.6
   Partner Dashboard + Bulk Product Import
========================================================= */

const $ = id => document.getElementById(id);

/* =========================================================
   API HELPER
========================================================= */

async function api(url, options = {}) {
  const token = localStorage.getItem("verifyit_token");

  const requestOptions = {
    ...options
  };

  const headers = {
    ...(options.headers || {})
  };

  if (
    requestOptions.body &&
    typeof requestOptions.body !== "string"
  ) {
    headers["Content-Type"] = "application/json";

    requestOptions.body =
      JSON.stringify(requestOptions.body);
  }

  if (token) {
    headers.Authorization =
      `Bearer ${token}`;
  }

  requestOptions.headers =
    headers;

  const response =
    await fetch(
      url,
      requestOptions
    );

  let data = {};

  try {
    data =
      await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {

    if (
      response.status === 503 &&
      data.locked
    ) {
      throw new Error(
        "VerifyIt is currently under lockdown."
      );
    }

    throw new Error(
      data.error ||
      "Something went wrong."
    );
  }

  return data;
}

/* =========================================================
   IMAGE COMPRESSION
========================================================= */

function compressImage(file) {

  return new Promise(
    (resolve, reject) => {

      const reader =
        new FileReader();

      reader.onload = () => {

        const image =
          new Image();

        image.onload = () => {

          const maxSize = 1200;

          let width =
            image.width;

          let height =
            image.height;

          if (
            width > maxSize ||
            height > maxSize
          ) {

            if (
              width > height
            ) {

              height =
                Math.round(
                  height *
                  (maxSize / width)
                );

              width =
                maxSize;

            } else {

              width =
                Math.round(
                  width *
                  (maxSize / height)
                );

              height =
                maxSize;
            }
          }

          const canvas =
            document.createElement(
              "canvas"
            );

          canvas.width =
            width;

          canvas.height =
            height;

          const ctx =
            canvas.getContext(
              "2d"
            );

          ctx.drawImage(
            image,
            0,
            0,
            width,
            height
          );

          resolve(
            canvas.toDataURL(
              "image/jpeg",
              0.78
            )
          );
        };

        image.onerror = () => {

          reject(
            new Error(
              "Unable to read image."
            )
          );
        };

        image.src =
          reader.result;
      };

      reader.onerror = () => {

        reject(
          new Error(
            "Unable to load image."
          )
        );
      };

      reader.readAsDataURL(
        file
      );
    }
  );
}

/* =========================================================
   AUTH DISPLAY
========================================================= */

function showDashboard(
  business
) {

  if ($("authArea")) {
    $("authArea").hidden = true;
  }

  if ($("dashboard")) {
    $("dashboard").hidden = false;
  }

  if ($("businessName")) {

    $("businessName")
      .textContent =
      business?.name ||
      "Business Dashboard";
  }

  if ($("businessEmail")) {

    $("businessEmail")
      .textContent =
      business?.email || "";
  }

  loadDashboard();
}

function showAuth() {

  if ($("authArea")) {
    $("authArea").hidden = false;
  }

  if ($("dashboard")) {
    $("dashboard").hidden = true;
  }
}

/* =========================================================
   CURRENT USER
========================================================= */

async function loadCurrentUser() {

  const token =
    localStorage.getItem(
      "verifyit_token"
    );

  if (!token) {

    showAuth();

    return;
  }

  try {

    const business =
      await api(
        "/api/me"
      );

    showDashboard(
      business
    );

  } catch (error) {

    if (
      error.message ===
      "VerifyIt is currently under lockdown."
    ) {

      showDashboard({
        name:
          "VerifyIt Partner",
        email: ""
      });

      return;
    }

    localStorage.removeItem(
      "verifyit_token"
    );

    showAuth();
  }
}

/* =========================================================
   REGISTER
========================================================= */

function connectRegisterForm() {

  const form =
    $("registerForm");

  if (!form) {

    console.warn(
      "VerifyIt: registerForm not found."
    );

    return;
  }

  form.addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      try {

        const data =
          await api(
            "/api/register",
            {
              method:
                "POST",

              body: {
                name:
                  $("registerName")
                    ?.value
                    ?.trim() ||
                  "",

                email:
                  $("registerEmail")
                    ?.value
                    ?.trim() ||
                  "",

                password:
                  $("registerPassword")
                    ?.value ||
                  ""
              }
            }
          );

        if (!data.token) {

          throw new Error(
            "Registration succeeded but no login token was returned."
          );
        }

        localStorage.setItem(
          "verifyit_token",
          data.token
        );

        showDashboard(
          data.business
        );

      } catch (error) {

        alert(
          error.message ||
          "Registration failed."
        );
      }
    }
  );
}

/* =========================================================
   LOGIN
========================================================= */

function connectLoginForm() {

  const form =
    $("loginForm");

  if (!form) {

    console.error(
      "VerifyIt: loginForm not found."
    );

    return;
  }

  console.log(
    "VerifyIt: Login form connected."
  );

  form.addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      event.stopPropagation();

      console.log(
        "VerifyIt: Login submitted."
      );

      const emailInput =
        $("loginEmail");

      const passwordInput =
        $("loginPassword");

      if (
        !emailInput ||
        !passwordInput
      ) {

        alert(
          "Login form is missing the email or password field."
        );

        return;
      }

      const email =
        emailInput.value.trim();

      const password =
        passwordInput.value;

      if (!email) {

        alert(
          "Please enter your email address."
        );

        emailInput.focus();

        return;
      }

      if (!password) {

        alert(
          "Please enter your password."
        );

        passwordInput.focus();

        return;
      }

      const submitButton =
        form.querySelector(
          'button[type="submit"]'
        );

      const originalText =
        submitButton
          ? submitButton.textContent
          : "Login";

      if (submitButton) {

        submitButton.disabled =
          true;

        submitButton.textContent =
          "Logging in...";
      }

      try {

        const data =
          await api(
            "/api/login",
            {
              method:
                "POST",

              body: {
                email,
                password
              }
            }
          );

        console.log(
          "VerifyIt: Login response received."
        );

        if (!data.token) {

          throw new Error(
            "Login succeeded but no authentication token was returned."
          );
        }

        localStorage.setItem(
          "verifyit_token",
          data.token
        );

        showDashboard(
          data.business
        );

        /*
          Move directly to dashboard
          after successful login.
        */

        setTimeout(
          () => {

            if (
              $("dashboard")
            ) {

              $("dashboard")
                .scrollIntoView({
                  behavior:
                    "smooth",
                  block:
                    "start"
                });
            }

          },
          100
        );

      } catch (error) {

        console.error(
          "VerifyIt login error:",
          error
        );

        alert(
          error.message ||
          "Login failed."
        );

      } finally {

        if (submitButton) {

          submitButton.disabled =
            false;

          submitButton.textContent =
            originalText ||
            "Login";
        }
      }
    }
  );
}

/* =========================================================
   LOGOUT
========================================================= */

function logout() {

  localStorage.removeItem(
    "verifyit_token"
  );

  showAuth();

  window.scrollTo({
    top: 0,
    behavior: "smooth"
  });
}

window.logout =
  logout;

/* =========================================================
   SINGLE PRODUCT REGISTRATION
========================================================= */

function connectProductForm() {

  const form =
    $("productForm");

  if (!form) {
    return;
  }

  form.addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      try {

        let imageData = "";

        const imageInput =
          $("productImage");

        if (
          imageInput &&
          imageInput.files &&
          imageInput.files[0]
        ) {

          imageData =
            await compressImage(
              imageInput.files[0]
            );
        }

        const data =
          await api(
            "/api/products",
            {
              method:
                "POST",

              body: {

                brand:
                  $("productBrand")
                    ?.value
                    ?.trim() ||
                  "",

                productName:
                  $("productName")
                    ?.value
                    ?.trim() ||
                  "",

                batch:
                  $("productBatch")
                    ?.value
                    ?.trim() ||
                  "",

                imageData
              }
            }
          );

        alert(
          "Product registered successfully.\n\n" +
          "VerifyIt Code: " +
          data.product.code
        );

        form.reset();

        await loadProducts();
        await loadStats();

      } catch (error) {

        alert(
          error.message
        );
      }
    }
  );
}

/* =========================================================
   LOAD PRODUCTS
========================================================= */

async function loadProducts() {

  try {

    const data =
      await api(
        "/api/products"
      );

    const products =
      data.products || [];

    const container =
      $("productList") ||
      $("productsList") ||
      $("catalogList") ||
      $("productCatalog");

    if (!container) {
      return;
    }

    if (!products.length) {

      container.innerHTML = `
        <div class="empty-state">
          No products registered yet.
        </div>
      `;

      return;
    }

    container.innerHTML =
      products
        .map(
          product => `

        <div
          class="product-card"
          data-code="${escapeHtml(
            product.code
          )}"
        >

          <div
            class="product-card-header"
          >

            <strong>
              ${escapeHtml(
                product.brand
              )}
            </strong>

            <span
              class="product-status"
            >
              ${escapeHtml(
                product.status
              )}
            </span>

          </div>

          <div
            class="product-card-body"
          >

            <div>
              <strong>
                Product
              </strong>
              <br>
              ${escapeHtml(
                product.productName
              )}
            </div>

            <div>
              <strong>
                Batch
              </strong>
              <br>
              ${escapeHtml(
                product.batch ||
                "—"
              )}
            </div>

            <div>
              <strong>
                Code
              </strong>
              <br>
              <code>
                ${escapeHtml(
                  product.code
                )}
              </code>
            </div>

            <div>
              <strong>
                Checks
              </strong>
              <br>
              ${Number(
                product.verificationCount ||
                0
              )}
            </div>

          </div>

          <div
            class="product-card-actions"
          >

            <button
              type="button"
              onclick="showProductQR('${escapeJs(
                product.code
              )}')"
            >
              QR
            </button>

            <button
              type="button"
              onclick="copyVerificationCode('${escapeJs(
                product.code
              )}')"
            >
              Copy Code
            </button>

            <button
              type="button"
              onclick="changeProductStatus('${escapeJs(
                product.code
              )}','disabled')"
            >
              Disable
            </button>

            <button
              type="button"
              onclick="deleteProduct('${escapeJs(
                product.code
              )}')"
            >
              Delete
            </button>

          </div>

        </div>
      `
        )
        .join("");

  } catch (error) {

    if (
      error.message ===
      "VerifyIt is currently under lockdown."
    ) {
      return;
    }

    console.error(
      "Unable to load products:",
      error
    );
  }
}

/* =========================================================
   LOAD DASHBOARD STATS
========================================================= */

async function loadStats() {

  try {

    const data =
      await api(
        "/api/stats"
      );

    if ($("productCount")) {

      $("productCount")
        .textContent =
        data.products ?? 0;
    }

    if ($("totalProducts")) {

      $("totalProducts")
        .textContent =
        data.products ?? 0;
    }

    if ($("checkCount")) {

      $("checkCount")
        .textContent =
        data.totalChecks ?? 0;
    }

    if ($("totalChecks")) {

      $("totalChecks")
        .textContent =
        data.totalChecks ?? 0;
    }

    if ($("warningCount")) {

      $("warningCount")
        .textContent =
        data.warnings ?? 0;
    }

    if ($("totalWarnings")) {

      $("totalWarnings")
        .textContent =
        data.warnings ?? 0;
    }

  } catch (error) {

    console.error(
      "Stats error:",
      error
    );
  }
}

/* =========================================================
   DASHBOARD LOADER
========================================================= */

async function loadDashboard() {

  await Promise.allSettled([
    loadStats(),
    loadProducts()
  ]);
}

/* =========================================================
   REFRESH PRODUCTS
========================================================= */

function refreshProducts() {

  loadProducts();
  loadStats();
}

window.refreshProducts =
  refreshProducts;

/* =========================================================
   DELETE PRODUCT
========================================================= */

async function deleteProduct(
  code
) {

  const confirmed =
    confirm(
      "Delete this product?\n\n" +
      "This action cannot be undone."
    );

  if (!confirmed) {
    return;
  }

  try {

    await api(
      "/api/products/" +
      encodeURIComponent(
        code
      ),
      {
        method:
          "DELETE"
      }
    );

    await loadProducts();
    await loadStats();

  } catch (error) {

    alert(
      error.message
    );
  }
}

window.deleteProduct =
  deleteProduct;

/* =========================================================
   CHANGE PRODUCT STATUS
========================================================= */

async function changeProductStatus(
  code,
  status
) {

  try {

    await api(
      "/api/products/" +
      encodeURIComponent(
        code
      ) +
      "/status",
      {
        method:
          "PATCH",

        body: {
          status
        }
      }
    );

    await loadProducts();

  } catch (error) {

    alert(
      error.message
    );
  }
}

window.changeProductStatus =
  changeProductStatus;

/* =========================================================
   COPY CODE
========================================================= */

async function copyVerificationCode(
  code
) {

  try {

    await navigator.clipboard.writeText(
      code
    );

    alert(
      "Verification code copied:\n\n" +
      code
    );

  } catch {

    prompt(
      "Copy this verification code:",
      code
    );
  }
}

window.copyVerificationCode =
  copyVerificationCode;

/* =========================================================
   SHOW QR
========================================================= */

async function showProductQR(
  code
) {

  try {

    const data =
      await api(
        "/api/products/" +
        encodeURIComponent(
          code
        ) +
        "/qr"
      );

    showQRModal({
      code,
      url:
        data.url,
      image:
        data.data
    });

  } catch (error) {

    alert(
      error.message
    );
  }
}

window.showProductQR =
  showProductQR;

/* =========================================================
   QR MODAL
========================================================= */

function showQRModal({
  code,
  url,
  image
}) {

  removeQRModal();

  const modal =
    document.createElement(
      "div"
    );

  modal.id =
    "verifyitQRModal";

  modal.style.cssText = `
    position:fixed;
    inset:0;
    z-index:99999;
    background:rgba(0,0,0,.82);
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
  `;

  modal.innerHTML = `

    <div style="
      background:#fff;
      color:#111;
      width:min(420px,100%);
      border-radius:16px;
      padding:24px;
      text-align:center;
      box-sizing:border-box;
    ">

      <h2 style="margin-top:0;">
        VerifyIt QR Code
      </h2>

      <img
        src="${image}"
        alt="VerifyIt QR Code"
        style="
          width:280px;
          max-width:100%;
          height:auto;
          display:block;
          margin:15px auto;
        "
      >

      <p>
        <strong>Code:</strong>
        <br>
        ${escapeHtml(code)}
      </p>

      <p style="
        font-size:12px;
        word-break:break-all;
      ">
        ${escapeHtml(url)}
      </p>

      <div style="
        display:flex;
        gap:8px;
        justify-content:center;
        flex-wrap:wrap;
      ">

        <button
          type="button"
          id="verifyitQRDownload"
        >
          Save QR
        </button>

        <button
          type="button"
          id="verifyitQRClose"
        >
          Close
        </button>

      </div>

    </div>
  `;

  document.body.appendChild(
    modal
  );

  $("verifyitQRClose")
    .addEventListener(
      "click",
      removeQRModal
    );

  $("verifyitQRDownload")
    .addEventListener(
      "click",
      () => {

        const link =
          document.createElement(
            "a"
          );

        link.href =
          image;

        link.download =
          `verifyit-${code}.png`;

        document.body.appendChild(
          link
        );

        link.click();

        link.remove();
      }
    );

  modal.addEventListener(
    "click",
    event => {

      if (
        event.target ===
        modal
      ) {
        removeQRModal();
      }
    }
  );
}

function removeQRModal() {

  const modal =
    $("verifyitQRModal");

  if (modal) {
    modal.remove();
  }
}

/* =========================================================
   V1.6 BULK IMPORT
========================================================= */

let bulkProducts = [];

function openBulkImport() {

  createBulkImportModal();
}

window.openBulkImport =
  openBulkImport;

function createBulkImportModal() {

  removeBulkImportModal();

  const modal =
    document.createElement(
      "div"
    );

  modal.id =
    "verifyitBulkImportModal";

  modal.style.cssText = `
    position:fixed;
    inset:0;
    z-index:99998;
    background:rgba(0,0,0,.82);
    display:flex;
    align-items:center;
    justify-content:center;
    padding:15px;
    overflow:auto;
  `;

  modal.innerHTML = `

    <div style="
      background:#fff;
      color:#111;
      width:min(760px,100%);
      max-height:95vh;
      overflow:auto;
      border-radius:16px;
      padding:24px;
      box-sizing:border-box;
    ">

      <div style="
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:10px;
      ">

        <div>

          <h2 style="margin:0;">
            BULK PRODUCT IMPORT
          </h2>

          <p style="
            margin:6px 0 0;
          ">
            Import up to 50 products at once.
          </p>

        </div>

        <button
          type="button"
          id="verifyitBulkClose"
        >
          ✕
        </button>

      </div>

      <hr>

      <div style="
        background:#f4f4f4;
        border-radius:10px;
        padding:15px;
        margin-bottom:15px;
      ">

        <strong>
          Supported columns
        </strong>

        <p style="
          margin:8px 0 0;
          font-size:14px;
        ">
          Brand, Product, Batch
        </p>

        <p style="
          margin:8px 0 0;
          font-size:13px;
        ">
          Example:
          <br>

          <code>
            Brand A, Product One, BATCH-001
          </code>

          <br>

          <code>
            Brand A, Product Two, BATCH-002
          </code>

        </p>

      </div>

      <div style="
        border:2px dashed #aaa;
        border-radius:12px;
        padding:25px;
        text-align:center;
      ">

        <p>
          Choose a CSV or text file.
        </p>

        <input
          id="verifyitBulkFile"
          type="file"
          accept=".csv,.txt"
          style="max-width:100%;"
        >

      </div>

      <div
        id="verifyitBulkPreview"
        style="margin-top:20px;"
      ></div>

      <div
        id="verifyitBulkStatus"
        style="
          margin-top:15px;
          font-weight:bold;
        "
      ></div>

      <div style="
        display:flex;
        gap:10px;
        justify-content:flex-end;
        flex-wrap:wrap;
        margin-top:20px;
      ">

        <button
          type="button"
          id="verifyitBulkCancel"
        >
          Cancel
        </button>

        <button
          type="button"
          id="verifyitBulkImport"
          disabled
        >
          Import Products
        </button>

      </div>

      <div
        id="verifyitBulkResults"
        style="margin-top:20px;"
      ></div>

    </div>
  `;

  document.body.appendChild(
    modal
  );

  $("verifyitBulkClose")
    ?.addEventListener(
      "click",
      removeBulkImportModal
    );

  $("verifyitBulkCancel")
    ?.addEventListener(
      "click",
      removeBulkImportModal
    );

  $("verifyitBulkFile")
    ?.addEventListener(
      "change",
      handleBulkFile
    );

  $("verifyitBulkImport")
    ?.addEventListener(
      "click",
      submitBulkProducts
    );
}

/* =========================================================
   READ BULK FILE
========================================================= */

function handleBulkFile(
  event
) {

  const file =
    event.target.files?.[0];

  bulkProducts = [];

  if (!file) {
    return;
  }

  const reader =
    new FileReader();

  reader.onload = () => {

    try {

      const text =
        String(
          reader.result || ""
        );

      bulkProducts =
        parseCSVProducts(
          text
        );

      renderBulkPreview();

    } catch (error) {

      showBulkStatus(
        error.message,
        true
      );
    }
  };

  reader.onerror = () => {

    showBulkStatus(
      "Unable to read the selected file.",
      true
    );
  };

  reader.readAsText(
    file
  );
}

/* =========================================================
   CSV PARSER
========================================================= */

function parseCSVProducts(
  text
) {

  const lines =
    text
      .replace(
        /^\uFEFF/,
        ""
      )
      .split(/\r?\n/)
      .map(
        line =>
          line.trim()
      )
      .filter(Boolean);

  if (!lines.length) {

    throw new Error(
      "The selected file is empty."
    );
  }

  const rows =
    lines.map(
      parseCSVLine
    );

  let startIndex = 0;

  const first =
    rows[0].map(
      value =>
        value
          .toLowerCase()
          .trim()
    );

  if (
    first.some(
      value =>
        [
          "brand",
          "product",
          "product name",
          "productname",
          "batch"
        ].includes(value)
    )
  ) {
    startIndex = 1;
  }

  const products = [];

  for (
    let i = startIndex;
    i < rows.length;
    i++
  ) {

    const row =
      rows[i];

    if (!row.length) {
      continue;
    }

    const brand =
      String(
        row[0] || ""
      ).trim();

    const productName =
      String(
        row[1] || ""
      ).trim();

    const batch =
      String(
        row[2] || ""
      ).trim();

    if (
      !brand &&
      !productName &&
      !batch
    ) {
      continue;
    }

    if (!brand) {

      throw new Error(
        `Row ${i + 1}: Brand is missing.`
      );
    }

    if (!productName) {

      throw new Error(
        `Row ${i + 1}: Product name is missing.`
      );
    }

    products.push({
      brand,
      productName,
      batch
    });
  }

  if (!products.length) {

    throw new Error(
      "No valid products were found."
    );
  }

  if (products.length > 50) {

    throw new Error(
      "Maximum 50 products per import."
    );
  }

  return products;
}

function parseCSVLine(
  line
) {

  const result = [];

  let current = "";

  let insideQuotes =
    false;

  for (
    let i = 0;
    i < line.length;
    i++
  ) {

    const char =
      line[i];

    if (char === '"') {

      if (
        insideQuotes &&
        line[i + 1] === '"'
      ) {

        current += '"';

        i++;

        continue;
      }

      insideQuotes =
        !insideQuotes;

      continue;
    }

    if (
      char === "," &&
      !insideQuotes
    ) {

      result.push(
        current.trim()
      );

      current = "";

      continue;
    }

    current += char;
  }

  result.push(
    current.trim()
  );

  return result;
}

/* =========================================================
   BULK PREVIEW
========================================================= */

function renderBulkPreview() {

  const preview =
    $("verifyitBulkPreview");

  const importButton =
    $("verifyitBulkImport");

  if (
    !preview ||
    !importButton
  ) {
    return;
  }

  if (!bulkProducts.length) {

    preview.innerHTML =
      "";

    importButton.disabled =
      true;

    return;
  }

  importButton.disabled =
    false;

  const visibleProducts =
    bulkProducts.slice(
      0,
      10
    );

  preview.innerHTML = `

    <h3>
      Import Preview
    </h3>

    <p>
      ${bulkProducts.length}
      product(s) ready.
    </p>

    <div style="
      overflow:auto;
      border:1px solid #ddd;
      border-radius:8px;
    ">

      <table style="
        width:100%;
        border-collapse:collapse;
      ">

        <thead>

          <tr>

            <th style="
              padding:8px;
              text-align:left;
            ">
              #
            </th>

            <th style="
              padding:8px;
              text-align:left;
            ">
              Brand
            </th>

            <th style="
              padding:8px;
              text-align:left;
            ">
              Product
            </th>

            <th style="
              padding:8px;
              text-align:left;
            ">
              Batch
            </th>

          </tr>

        </thead>

        <tbody>

          ${visibleProducts
            .map(
              (
                product,
                index
              ) => `

              <tr>

                <td style="
                  padding:8px;
                ">
                  ${index + 1}
                </td>

                <td style="
                  padding:8px;
                ">
                  ${escapeHtml(
                    product.brand
                  )}
                </td>

                <td style="
                  padding:8px;
                ">
                  ${escapeHtml(
                    product.productName
                  )}
                </td>

                <td style="
                  padding:8px;
                ">
                  ${escapeHtml(
                    product.batch ||
                    "—"
                  )}
                </td>

              </tr>
            `
            )
            .join("")}

        </tbody>

      </table>

    </div>

    ${
      bulkProducts.length > 10
        ? `
          <p style="font-size:13px;">
            Showing first 10 of
            ${bulkProducts.length}
            products.
          </p>
        `
        : ""
    }
  `;

  showBulkStatus(
    "Ready to import.",
    false
  );
}

/* =========================================================
   SUBMIT BULK PRODUCTS
========================================================= */

async function submitBulkProducts() {

  if (!bulkProducts.length) {
    return;
  }

  const button =
    $("verifyitBulkImport");

  if (!button) {
    return;
  }

  button.disabled =
    true;

  showBulkStatus(
    "Registering products and generating QR codes...",
    false
  );

  try {

    const data =
      await api(
        "/api/products/bulk",
        {
          method:
            "POST",

          body: {
            products:
              bulkProducts
          }
        }
      );

    showBulkStatus(
      `Successfully registered ${data.count} product(s).`,
      false
    );

    renderBulkResults(
      data.products || []
    );

    await loadProducts();
    await loadStats();

    bulkProducts = [];

  } catch (error) {

    showBulkStatus(
      error.message,
      true
    );

    button.disabled =
      false;
  }
}

/* =========================================================
   BULK RESULTS
========================================================= */

function renderBulkResults(
  products
) {

  const container =
    $("verifyitBulkResults");

  if (!container) {
    return;
  }

  container.innerHTML = `

    <h3>
      Generated Products
    </h3>

    <p>
      Each product now has a unique VerifyIt
      code and QR verification link.
    </p>

    <div style="
      display:flex;
      flex-direction:column;
      gap:10px;
    ">

      ${products
        .map(
          product => `

          <div style="
            border:1px solid #ddd;
            border-radius:10px;
            padding:12px;
          ">

            <strong>
              ${escapeHtml(
                product.brand
              )}
            </strong>

            <br>

            ${escapeHtml(
              product.productName
            )}

            <br><br>

            <code>
              ${escapeHtml(
                product.code
              )}
            </code>

            <br><br>

            <button
              type="button"
              onclick="showBulkQR('${escapeJs(
                product.code
              )}','${escapeJs(
                product.qrData
              )}','${escapeJs(
                product.qrUrl
              )}')"
            >
              View QR
            </button>

            <button
              type="button"
              onclick="copyVerificationCode('${escapeJs(
                product.code
              )}')"
            >
              Copy Code
            </button>

          </div>
        `
        )
        .join("")}

    </div>
  `;
}

/* =========================================================
   BULK QR
========================================================= */

function showBulkQR(
  code,
  qrData,
  qrUrl
) {

  showQRModal({
    code,
    url:
      qrUrl,
    image:
      qrData
  });
}

window.showBulkQR =
  showBulkQR;

/* =========================================================
   BULK STATUS
========================================================= */

function showBulkStatus(
  message,
  isError
) {

  const box =
    $("verifyitBulkStatus");

  if (!box) {
    return;
  }

  box.textContent =
    message;

  box.style.color =
    isError
      ? "#b00020"
      : "#111";
}

/* =========================================================
   REMOVE BULK MODAL
========================================================= */

function removeBulkImportModal() {

  const modal =
    $("verifyitBulkImportModal");

  if (modal) {
    modal.remove();
  }

  bulkProducts = [];
}

window.removeBulkImportModal =
  removeBulkImportModal;

/* =========================================================
   CONNECT BULK BUTTON
========================================================= */

function connectBulkButton() {

  const button =
    $("bulkImportButton");

  if (!button) {
    return;
  }

  button.addEventListener(
    "click",
    event => {

      event.preventDefault();

      openBulkImport();
    }
  );
}

/* =========================================================
   QUICK ACTION / ANCHOR SUPPORT
========================================================= */

function connectBulkLinks() {

  document
    .querySelectorAll(
      'a[href="#bulk-import"]'
    )
    .forEach(
      link => {

        link.addEventListener(
          "click",
          event => {

            event.preventDefault();

            const section =
              $("bulk-import");

            if (section) {

              section.scrollIntoView({
                behavior:
                  "smooth"
              });
            }

            openBulkImport();
          }
        );
      }
    );
}

/* =========================================================
   PUBLIC VERIFICATION
========================================================= */

async function verifyProduct(
  code
) {

  const cleanCode =
    String(
      code || ""
    )
      .trim()
      .toUpperCase();

  if (!cleanCode) {
    return;
  }

  try {

    const data =
      await api(
        "/api/verify/" +
        encodeURIComponent(
          cleanCode
        )
      );

    displayVerificationResult(
      data
    );

  } catch (error) {

    displayVerificationResult({
      success:
        false,

      result:
        "not_verified",

      message:
        error.message
    });
  }
}

window.verifyProduct =
  verifyProduct;

/* =========================================================
   VERIFICATION RESULT
========================================================= */

function displayVerificationResult(
  data
) {

  const container =
    $("verificationResult") ||
    $("verifyResult") ||
    $("verificationResultArea");

  if (!container) {

    alert(
      data.message ||
      "Verification complete."
    );

    return;
  }

  const product =
    data.product || {};

  const isAuthentic =
    data.result ===
    "authentic";

  const isWarning =
    data.result ===
    "warning";

  let title =
    "Product Not Verified";

  if (isAuthentic) {

    title =
      "Product Verified";

  } else if (isWarning) {

    title =
      "Verification Warning";
  }

  container.hidden =
    false;

  container.innerHTML = `

    <div
      class="verification-result"
    >

      <h2>
        ${escapeHtml(
          title
        )}
      </h2>

      <p>
        ${escapeHtml(
          data.message ||
          ""
        )}
      </p>

      ${
        product.brand
          ? `
            <p>
              <strong>
                Brand:
              </strong>
              ${escapeHtml(
                product.brand
              )}
            </p>
          `
          : ""
      }

      ${
        product.productName
          ? `
            <p>
              <strong>
                Product:
              </strong>
              ${escapeHtml(
                product.productName
              )}
            </p>
          `
          : ""
      }

      ${
        product.batch
          ? `
            <p>
              <strong>
                Batch:
              </strong>
              ${escapeHtml(
                product.batch
              )}
            </p>
          `
          : ""
      }

      ${
        product.code
          ? `
            <p>
              <strong>
                Code:
              </strong>

              <code>
                ${escapeHtml(
                  product.code
                )}
              </code>

            </p>
          `
          : ""
      }

      ${
        product.imageData
          ? `
            <img
              src="${product.imageData}"
              alt="Verified product"
              style="
                max-width:240px;
                width:100%;
                border-radius:12px;
              "
            >
          `
          : ""
      }

    </div>
  `;

  container.scrollIntoView({
    behavior:
      "smooth",

    block:
      "center"
  });
}

/* =========================================================
   PUBLIC VERIFICATION FORM
========================================================= */

function connectVerificationForm() {

  const form =
    $("verifyForm");

  if (!form) {
    return;
  }

  form.addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      const input =
        $("verifyCode") ||
        $("verificationCode") ||
        $("codeInput");

      if (!input) {
        return;
      }

      await verifyProduct(
        input.value
      );
    }
  );
}

/* =========================================================
   AUTO VERIFY FROM QR LINK
========================================================= */

function autoVerifyFromUrl() {

  const params =
    new URLSearchParams(
      window.location.search
    );

  const verifyCode =
    params.get(
      "verify"
    );

  if (!verifyCode) {
    return;
  }

  const input =
    $("verifyCode") ||
    $("verificationCode") ||
    $("codeInput");

  if (input) {

    input.value =
      verifyCode;
  }

  setTimeout(
    () => {

      verifyProduct(
        verifyCode
      );

    },
    300
  );
}

/* =========================================================
   HTML SAFETY HELPERS
========================================================= */

function escapeHtml(
  value
) {

  return String(
    value ?? ""
  )
    .replaceAll(
      "&",
      "&amp;"
    )
    .replaceAll(
      "<",
      "&lt;"
    )
    .replaceAll(
      ">",
      "&gt;"
    )
    .replaceAll(
      '"',
      "&quot;"
    )
    .replaceAll(
      "'",
      "&#039;"
    );
}

function escapeJs(
  value
) {

  return String(
    value ?? ""
  )
    .replaceAll(
      "\\",
      "\\\\"
    )
    .replaceAll(
      "'",
      "\\'"
    )
    .replaceAll(
      "\n",
      "\\n"
    )
    .replaceAll(
      "\r",
      "\\r"
    );
}

/* =========================================================
   STARTUP
========================================================= */

function startVerifyItApp() {

  console.log(
    "VerifyIt V1.6 app.js loaded."
  );

  try {

    connectLoginForm();

  } catch (error) {

    console.error(
      "Login initialization error:",
      error
    );
  }

  try {

    connectRegisterForm();

  } catch (error) {

    console.error(
      "Register initialization error:",
      error
    );
  }

  try {

    connectProductForm();

  } catch (error) {

    console.error(
      "Product form initialization error:",
      error
    );
  }

  try {

    connectBulkButton();

  } catch (error) {

    console.error(
      "Bulk button initialization error:",
      error
    );
  }

  try {

    connectBulkLinks();

  } catch (error) {

    console.error(
      "Bulk links initialization error:",
      error
    );
  }

  try {

    connectVerificationForm();

  } catch (error) {

    console.error(
      "Verification initialization error:",
      error
    );
  }

  try {

    loadCurrentUser();

  } catch (error) {

    console.error(
      "Current user initialization error:",
      error
    );
  }

  try {

    autoVerifyFromUrl();

  } catch (error) {

    console.error(
      "Auto verification initialization error:",
      error
    );
  }
}

/*
   IMPORTANT:

   If app.js loads before DOMContentLoaded,
   wait for the DOM.

   If app.js loads after DOMContentLoaded,
   start immediately.

   This prevents the login form from
   falling back to normal HTML submission.
*/

if (
  document.readyState ===
  "loading"
) {

  document.addEventListener(
    "DOMContentLoaded",
    startVerifyItApp
  );

} else {

  startVerifyItApp();

}
```
