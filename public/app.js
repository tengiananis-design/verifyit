const $ = id =>
  document.getElementById(id);

/* =========================================================
   VERIFYIT APP.JS
   V1.5 LOCK IN COMPATIBLE
   V1.6 READY
========================================================= */


/* =========================================================
   API HELPER
========================================================= */

async function api(url, options = {}) {

  const token =
    localStorage.getItem("verifyit_token");

  const headers = {
    ...(options.headers || {})
  };

  if (
    options.body &&
    typeof options.body !== "string"
  ) {
    headers["Content-Type"] =
      "application/json";

    options.body =
      JSON.stringify(options.body);
  }

  if (token) {
    headers.Authorization =
      `Bearer ${token}`;
  }

  let response;

  try {

    response =
      await fetch(
        url,
        {
          ...options,
          headers
        }
      );

  } catch (error) {

    throw new Error(
      "Network error. Please check your connection."
    );
  }

  let data = {};

  try {

    data =
      await response.json();

  } catch {

    data = {};
  }

  if (!response.ok) {

    /*
      IMPORTANT:
      Lockdown is NOT an expired login.
      Never delete the user's token here.
    */

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

      reader.onload =
        () => {

          const image =
            new Image();

          image.onload =
            () => {

              const maxSize =
                1200;

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
                      (
                        maxSize /
                        width
                      )
                    );

                  width =
                    maxSize;

                } else {

                  width =
                    Math.round(
                      width *
                      (
                        maxSize /
                        height
                      )
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

          image.onerror =
            () =>
              reject(
                new Error(
                  "Unable to read image."
                )
              );

          image.src =
            reader.result;
        };

      reader.onerror =
        () =>
          reject(
            new Error(
              "Unable to load image."
            )
          );

      reader.readAsDataURL(file);
    }
  );
}


/* =========================================================
   AUTH DISPLAY
========================================================= */

function showDashboard(business) {

  if ($("authArea")) {

    $("authArea").hidden =
      true;
  }

  if ($("dashboard")) {

    $("dashboard").hidden =
      false;
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
      business?.email ||
      "";
  }

  loadDashboard();
}


function showAuth() {

  if ($("authArea")) {

    $("authArea").hidden =
      false;
  }

  if ($("dashboard")) {

    $("dashboard").hidden =
      true;
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

    /*
      Lockdown does not invalidate
      the current session.
    */

    if (
      error.message ===
      "VerifyIt is currently under lockdown."
    ) {

      showDashboard({
        name:
          "VerifyIt Partner",
        email:
          ""
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

if ($("registerForm")) {

  $("registerForm")
    .addEventListener(
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
                      .trim(),

                  email:
                    $("registerEmail")
                      ?.value
                      .trim(),

                  password:
                    $("registerPassword")
                      ?.value
                }
              }
            );

          localStorage.setItem(
            "verifyit_token",
            data.token
          );

          showDashboard(
            data.business
          );

        } catch (error) {

          alert(
            error.message
          );
        }
      }
    );
}


/* =========================================================
   LOGIN
========================================================= */

if ($("loginForm")) {

  $("loginForm")
    .addEventListener(
      "submit",
      async event => {

        event.preventDefault();

        try {

          const data =
            await api(
              "/api/login",
              {
                method:
                  "POST",

                body: {

                  email:
                    $("loginEmail")
                      ?.value
                      .trim(),

                  password:
                    $("loginPassword")
                      ?.value
                }
              }
            );

          localStorage.setItem(
            "verifyit_token",
            data.token
          );

          showDashboard(
            data.business
          );

        } catch (error) {

          alert(
            error.message
          );
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

  window.location.hash =
    "business";
}


if ($("logoutButton")) {

  $("logoutButton")
    .addEventListener(
      "click",
      logout
    );
}


/* =========================================================
   REGISTER PRODUCT
========================================================= */

if ($("productForm")) {

  $("productForm")
    .addEventListener(
      "submit",
      async event => {

        event.preventDefault();

        const button =
          event.submitter ||
          $("registerProductButton");

        if (button) {

          button.disabled =
            true;
        }

        try {

          let imageData =
            null;

          const imageInput =
            $("productImage");

          if (
            imageInput &&
            imageInput.files &&
            imageInput.files.length
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
                      .trim(),

                  productName:
                    $("productName")
                      ?.value
                      .trim(),

                  batch:
                    $("productBatch")
                      ?.value
                      .trim(),

                  imageData
                }
              }
            );

          alert(
            "Product registered successfully.\n\nVerification Code: " +
            (
              data.product?.code ||
              data.code ||
              "Generated"
            )
          );

          event.target.reset();

          await loadDashboard();

        } catch (error) {

          alert(
            error.message
          );

        } finally {

          if (button) {

            button.disabled =
              false;
          }
        }
      }
    );
}


/* =========================================================
   LOAD PRODUCTS
========================================================= */

async function loadProducts() {

  const container =
    $("productCatalog");

  if (!container) {
    return;
  }

  try {

    const data =
      await api(
        "/api/products"
      );

    const products =
      Array.isArray(data)
        ? data
        : (
            data.products ||
            []
          );

    if (!products.length) {

      container.innerHTML = `
        <div class="empty-state">
          <p>No products registered yet.</p>
        </div>
      `;

      return;
    }

    container.innerHTML =
      products
        .map(product => {

          const image =
            product.image_data ||
            product.imageData;

          const status =
            product.status ||
            "active";

          const checks =
            product.verification_count ||
            0;

          return `
            <div class="product-card">

              ${
                image
                  ? `
                    <img
                      src="${image}"
                      alt="${escapeHtml(
                        product.product_name ||
                        product.productName ||
                        "Product"
                      )}"
                      class="product-image"
                    >
                  `
                  : ""
              }

              <div class="product-info">

                <h3>
                  ${escapeHtml(
                    product.product_name ||
                    product.productName ||
                    "Unnamed Product"
                  )}
                </h3>

                <p>
                  <strong>Brand:</strong>
                  ${escapeHtml(
                    product.brand || ""
                  )}
                </p>

                <p>
                  <strong>Batch:</strong>
                  ${escapeHtml(
                    product.batch || ""
                  )}
                </p>

                <p>
                  <strong>Code:</strong>
                  <span class="product-code">
                    ${escapeHtml(
                      product.code || ""
                    )}
                  </span>
                </p>

                <p>
                  <strong>Status:</strong>
                  ${escapeHtml(status)}
                </p>

                <p>
                  <strong>Verification Checks:</strong>
                  ${checks}
                </p>

                <div class="product-actions">

                  <button
                    type="button"
                    onclick="generateQR('${escapeJs(
                      product.code || ""
                    )}')"
                  >
                    QR Code
                  </button>

                  <button
                    type="button"
                    onclick="changeProductStatus(
                      '${escapeJs(
                        product.code || ""
                      )}',
                      '${status === "active"
                        ? "disabled"
                        : "active"}'
                    )"
                  >
                    ${
                      status === "active"
                        ? "Disable"
                        : "Activate"
                    }
                  </button>

                  <button
                    type="button"
                    onclick="deleteProduct(
                      '${escapeJs(
                        product.code || ""
                      )}'
                    )"
                  >
                    Delete
                  </button>

                </div>

              </div>

            </div>
          `;

        })
        .join("");

  } catch (error) {

    container.innerHTML = `
      <div class="error-state">
        ${escapeHtml(
          error.message
        )}
      </div>
    `;
  }
}


/* =========================================================
   DASHBOARD STATS
========================================================= */

async function loadStats() {

  try {

    const data =
      await api(
        "/api/stats"
      );

    const products =
      data.products ??
      data.totalProducts ??
      data.total_products ??
      0;

    const checks =
      data.totalChecks ??
      data.total_checks ??
      data.verifications ??
      0;

    const warnings =
      data.warnings ??
      data.warningCount ??
      0;

    if ($("productCount")) {

      $("productCount")
        .textContent =
        products;
    }

    if ($("totalChecks")) {

      $("totalChecks")
        .textContent =
        checks;
    }

    if ($("warningCount")) {

      $("warningCount")
        .textContent =
        warnings;
    }

  } catch (error) {

    /*
      Stats failure should not
      break the dashboard.
    */

    console.warn(
      "Unable to load stats:",
      error.message
    );
  }
}


/* =========================================================
   DASHBOARD LOADER
========================================================= */

async function loadDashboard() {

  await Promise.allSettled([
    loadProducts(),
    loadStats()
  ]);
}


/* =========================================================
   REFRESH CATALOG
========================================================= */

async function refreshCatalog() {

  await loadProducts();
  await loadStats();
}


if ($("refreshProductsButton")) {

  $("refreshProductsButton")
    .addEventListener(
      "click",
      refreshCatalog
    );
}


/* =========================================================
   CHANGE PRODUCT STATUS
========================================================= */

async function changeProductStatus(
  code,
  status
) {

  if (!code) {
    return;
  }

  try {

    await api(
      `/api/products/${encodeURIComponent(code)}/status`,
      {
        method:
          "PATCH",

        body: {
          status
        }
      }
    );

    await loadDashboard();

  } catch (error) {

    alert(
      error.message
    );
  }
}


/* =========================================================
   DELETE PRODUCT
========================================================= */

async function deleteProduct(
  code
) {

  if (!code) {
    return;
  }

  const confirmed =
    confirm(
      "Delete this product permanently?"
    );

  if (!confirmed) {
    return;
  }

  try {

    await api(
      `/api/products/${encodeURIComponent(code)}`,
      {
        method:
          "DELETE"
      }
    );

    await loadDashboard();

  } catch (error) {

    alert(
      error.message
    );
  }
}


/* =========================================================
   GENERATE QR
========================================================= */

async function generateQR(
  code
) {

  if (!code) {
    return;
  }

  try {

    const data =
      await api(
        `/api/products/${encodeURIComponent(code)}/qr`
      );

    const qr =
      data.qr ||
      data.qrCode ||
      data.dataUrl ||
      data.dataURL;

    if (!qr) {

      throw new Error(
        "QR code was not returned by the server."
      );
    }

    /*
      Use a temporary modal-like
      browser window so we don't
      depend on additional HTML.
    */

    const popup =
      window.open(
        "",
        "_blank",
        "width=500,height=600"
      );

    if (!popup) {

      throw new Error(
        "Please allow pop-ups to view the QR code."
      );
    }

    popup.document.write(`
      <!DOCTYPE html>

      <html>

      <head>

        <title>VerifyIt QR Code</title>

        <style>

          body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 30px;
          }

          img {
            max-width: 350px;
            width: 90%;
          }

          button {
            margin-top: 20px;
            padding: 10px 18px;
            cursor: pointer;
          }

        </style>

      </head>

      <body>

        <h2>VerifyIt QR Code</h2>

        <p>
          Product Code:
          <strong>
            ${escapeHtml(code)}
          </strong>
        </p>

        <img
          src="${escapeHtml(qr)}"
          alt="VerifyIt QR Code"
        >

        <br>

        <button
          onclick="window.print()"
        >
          Print QR Code
        </button>

      </body>

      </html>
    `);

    popup.document.close();

  } catch (error) {

    alert(
      error.message
    );
  }
}


/* =========================================================
   PUBLIC PRODUCT VERIFICATION
========================================================= */

if ($("verifyForm")) {

  $("verifyForm")
    .addEventListener(
      "submit",
      async event => {

        event.preventDefault();

        const codeInput =
          $("verifyCode");

        const result =
          $("verificationResult");

        const code =
          codeInput
            ?.value
            ?.trim();

        if (!code) {

          alert(
            "Please enter a verification code."
          );

          return;
        }

        if (result) {

          result.innerHTML =
            "Checking...";
        }

        try {

          const data =
            await api(
              `/api/verify/${encodeURIComponent(code)}`
            );

          if (!result) {

            alert(
              JSON.stringify(
                data,
                null,
                2
              )
            );

            return;
          }

          const product =
            data.product ||
            {};

          const success =
            data.success !== false;

          result.innerHTML = `

            <div class="
              verification-result
              ${success
                ? "verification-success"
                : "verification-warning"}
            ">

              <h3>
                ${
                  success
                    ? "Verification Result"
                    : "Verification Warning"
                }
              </h3>

              <p>
                ${
                  escapeHtml(
                    data.message ||
                    data.result ||
                    data.error ||
                    (
                      success
                        ? "Product verification completed."
                        : "Unable to verify this product."
                    )
                  )
                }
              </p>

              ${
                product.product_name ||
                product.productName
                  ? `
                    <p>
                      <strong>Product:</strong>
                      ${escapeHtml(
                        product.product_name ||
                        product.productName
                      )}
                    </p>
                  `
                  : ""
              }

              ${
                product.brand
                  ? `
                    <p>
                      <strong>Brand:</strong>
                      ${escapeHtml(
                        product.brand
                      )}
                    </p>
                  `
                  : ""
              }

              ${
                product.batch
                  ? `
                    <p>
                      <strong>Batch:</strong>
                      ${escapeHtml(
                        product.batch
                      )}
                    </p>
                  `
                  : ""
              }

              ${
                product.image_data ||
                product.imageData
                  ? `
                    <img
                      src="${
                        product.image_data ||
                        product.imageData
                      }"
                      alt="Verified product"
                      class="verified-product-image"
                    >
                  `
                  : ""
              }

            </div>
          `;

        } catch (error) {

          if (result) {

            result.innerHTML = `
              <div class="verification-error">
                ${escapeHtml(
                  error.message
                )}
              </div>
            `;

          } else {

            alert(
              error.message
            );
          }
        }
      }
    );
}


/* =========================================================
   BULK PRODUCTS
   V1.6 PLACEHOLDER
========================================================= */

/*
  The index.html already contains the
  V1.6 Bulk Products interface.

  However, the V1.5 backend currently
  has NO bulk endpoint.

  Therefore this button intentionally
  does NOT pretend to perform a bulk
  registration.

  Once the V1.6 backend is added, this
  handler will be replaced with the
  real CSV/Excel processing workflow.
*/

if ($("bulkImportButton")) {

  $("bulkImportButton")
    .addEventListener(
      "click",
      () => {

        alert(
          "Bulk Product Import is being prepared for VerifyIt V1.6."
        );

      }
    );
}


/* =========================================================
   HELPER FUNCTIONS
========================================================= */

function escapeHtml(value) {

  return String(
    value ?? ""
  )
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}


function escapeJs(value) {

  return String(
    value ?? ""
  )
    .replace(
      /\\/g,
      "\\\\"
    )
    .replace(
      /'/g,
      "\\'"
    )
    .replace(
      /"/g,
      '\\"'
    )
    .replace(
      /\n/g,
      "\\n"
    )
    .replace(
      /\r/g,
      "\\r"
    );
}


/* =========================================================
   INITIALIZATION
========================================================= */

document.addEventListener(
  "DOMContentLoaded",
  () => {

    loadCurrentUser();

  }
);
