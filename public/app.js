const $ = id =>
  document.getElementById(id);


/* -----------------------------
   API HELPER
----------------------------- */

async function api(
  url,
  options = {}
) {
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

  const response =
    await fetch(url, {
      ...options,
      headers
    });

  let data = {};

  try {
    data =
      await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      data.error ||
      "Something went wrong."
    );
  }

  return data;
}


/* -----------------------------
   IMAGE COMPRESSION
----------------------------- */

function compressImage(
  file
) {
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


/* -----------------------------
   AUTH DISPLAY
----------------------------- */

function showDashboard(
  business
) {

  $("authArea").hidden =
    true;

  $("dashboard").hidden =
    false;

  $("businessName")
    .textContent =
    business?.name ||
    "Business Dashboard";

  $("businessEmail")
    .textContent =
    business?.email || "";

  loadDashboard();
}


function showAuth() {

  $("authArea").hidden =
    false;

  $("dashboard").hidden =
    true;
}


/* -----------------------------
   LOAD CURRENT USER
----------------------------- */

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

  } catch {

    localStorage.removeItem(
      "verifyit_token"
    );

    showAuth();
  }
}


/* -----------------------------
   REGISTER
----------------------------- */

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
              method: "POST",
              body: {
                name:
                  $("registerName")
                    .value
                    .trim(),

                email:
                  $("registerEmail")
                    .value
                    .trim(),

                password:
                  $("registerPassword")
                    .value
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


/* -----------------------------
   LOGIN
----------------------------- */

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
              method: "POST",
              body: {
                email:
                  $("loginEmail")
                    .value
                    .trim(),

                password:
                  $("loginPassword")
                    .value
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


/* -----------------------------
   LOGOUT
----------------------------- */

$("logoutButton")
  .addEventListener(
    "click",
    () => {

      localStorage.removeItem(
        "verifyit_token"
      );

      showAuth();
    }
  );


/* -----------------------------
   PRODUCT IMAGE PREVIEW
----------------------------- */

$("productImage")
  .addEventListener(
    "change",
    async event => {

      const file =
        event.target.files?.[0];

      if (!file) {

        $("imagePreview").hidden =
          true;

        return;
      }

      try {

        const imageData =
          await compressImage(
            file
          );

        $("productImagePreview")
          .src =
          imageData;

        $("imagePreview")
          .hidden =
          false;

      } catch (error) {

        alert(
          error.message
        );

        event.target.value =
          "";

        $("imagePreview").hidden =
          true;
      }
    }
  );


/* -----------------------------
   REGISTER PRODUCT
----------------------------- */

$("productForm")
  .addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      try {

        const file =
          $("productImage")
            .files?.[0];

        let imageData =
          "";

        if (file) {

          imageData =
            await compressImage(
              file
            );
        }

        const product =
          await api(
            "/api/products",
            {
              method: "POST",

              body: {
                brand:
                  $("productBrand")
                    .value
                    .trim(),

                productName:
                  $("productName")
                    .value
                    .trim(),

                batch:
                  $("productBatch")
                    .value
                    .trim(),

                imageData
              }
            }
          );

        alert(
          `Product registered successfully.\n\nVerification code:\n${product.code}`
        );

        $("productForm")
          .reset();

        $("imagePreview")
          .hidden =
          true;

        await loadDashboard();

      } catch (error) {

        alert(
          error.message
        );
      }
    }
  );


/* -----------------------------
   LOAD DASHBOARD
----------------------------- */

async function loadDashboard() {

  try {

    const [
      stats,
      products
    ] =
      await Promise.all([
        api("/api/stats"),
        api("/api/products")
      ]);

    $("statProducts")
      .textContent =
      stats.products;

    $("statChecks")
      .textContent =
      stats.checks;

    $("statWarnings")
      .textContent =
      stats.warnings;

    renderProducts(
      products
    );

  } catch (error) {

    console.error(
      error
    );

    alert(
      error.message
    );
  }
}


/* -----------------------------
   RENDER PRODUCTS
----------------------------- */

function renderProducts(
  products
) {

  const container =
    $("productsList");

  if (!products.length) {

    container.innerHTML =
      `
      <div class="empty-state">
        No products registered yet.
      </div>
      `;

    return;
  }

  container.innerHTML =
    products
      .map(product => {

        const statusLabel =
          product.status ===
          "active"
            ? "Disable"
            : "Enable";

        const nextStatus =
          product.status ===
          "active"
            ? "disabled"
            : "active";

        return `
          <div
            class="product-card"
            data-product-code="${escapeHtml(product.code)}"
          >

            <div
              class="product-image-holder"
              data-image-code="${escapeHtml(product.code)}"
            >
              <div class="product-image-placeholder">
                No image
              </div>
            </div>


            <div class="product-info">

              <h4>
                ${escapeHtml(
                  product.productName
                )}
              </h4>

              <p>
                <strong>Brand:</strong>
                ${escapeHtml(
                  product.brand
                )}
              </p>

              <p>
                <strong>Batch:</strong>
                ${escapeHtml(
                  product.batch || "—"
                )}
              </p>

              <p>
                <strong>Code:</strong>
                <code>
                  ${escapeHtml(
                    product.code
                  )}
                </code>
              </p>

              <p>
                <strong>Status:</strong>
                ${escapeHtml(
                  product.status
                )}
              </p>

              <p>
                <strong>Checks:</strong>
                ${product.verificationCount}
              </p>

            </div>


            <div class="product-actions">

              <button
                class="button small"
                onclick="makeQR('${escapeJs(product.code)}')"
              >
                QR
              </button>

              <button
                class="button small"
                onclick="replaceProductImage('${escapeJs(product.code)}')"
              >
                Image
              </button>

              <button
                class="button small"
                onclick="setStatus('${escapeJs(product.code)}','${nextStatus}')"
              >
                ${statusLabel}
              </button>

              <button
                class="button small danger"
                onclick="deleteProduct('${escapeJs(product.code)}')"
              >
                Delete
              </button>

            </div>

          </div>
        `;
      })
      .join("");

  products.forEach(
    product => {

      loadProductImage(
        product.code
      );
    }
  );
}


/* -----------------------------
   LOAD PRODUCT IMAGE
----------------------------- */

async function loadProductImage(
  code
) {

  try {

    const data =
      await api(
        "/api/products/" +
        encodeURIComponent(
          code
        ) +
        "/image"
      );

    const holders =
      document.querySelectorAll(
        "[data-image-code]"
      );

    let holder = null;

    holders.forEach(
      item => {

        if (
          item.dataset.imageCode ===
          code
        ) {
          holder = item;
        }
      }
    );

    if (!holder) {
      return;
    }

    if (
      data.imageData
    ) {

      holder.innerHTML =
        `
        <img
          src="${data.imageData}"
          alt="Registered product"
          class="product-image"
        >
        `;

    } else {

      holder.innerHTML =
        `
        <div class="product-image-placeholder">
          No image
        </div>
        `;
    }

  } catch (error) {

    console.error(
      "Unable to load image:",
      error
    );
  }
}


/* -----------------------------
   REPLACE PRODUCT IMAGE
----------------------------- */

window.replaceProductImage =
  async code => {

    const input =
      document.createElement(
        "input"
      );

    input.type =
      "file";

    input.accept =
      "image/jpeg,image/png,image/webp";

    input.onchange =
      async () => {

        const file =
          input.files?.[0];

        if (!file) {
          return;
        }

        try {

          const imageData =
            await compressImage(
              file
            );

          await api(
            "/api/products/" +
            encodeURIComponent(
              code
            ) +
            "/image",
            {
              method: "PATCH",

              body: {
                imageData
              }
            }
          );

          alert(
            "Product image updated."
          );

          await loadDashboard();

        } catch (error) {

          alert(
            error.message
          );
        }
      };

    input.click();
  };


/* -----------------------------
   CHANGE STATUS
----------------------------- */

window.setStatus =
  async (
    code,
    status
  ) => {

    try {

      await api(
        "/api/products/" +
        encodeURIComponent(
          code
        ) +
        "/status",
        {
          method: "PATCH",

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
  };


/* -----------------------------
   DELETE PRODUCT
----------------------------- */

window.deleteProduct =
  async code => {

    const confirmed =
      confirm(
        "Delete this product permanently?"
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
          method: "DELETE"
        }
      );

      await loadDashboard();

    } catch (error) {

      alert(
        error.message
      );
    }
  };


/* -----------------------------
   GENERATE QR
----------------------------- */

window.makeQR =
  async code => {

    try {

      const data =
        await api(
          "/api/products/" +
          encodeURIComponent(
            code
          ) +
          "/qr"
        );

      const popup =
        window.open(
          "",
          "_blank"
        );

      if (!popup) {

        alert(
          "Please allow pop-ups for VerifyIt."
        );

        return;
      }

      popup.document.write(
        `
        <!doctype html>
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
              width: 500px;
              max-width: 90vw;
            }

            button {
              padding: 12px 20px;
              margin-top: 20px;
              cursor: pointer;
            }
          </style>
        </head>

        <body>

          <h2>VerifyIt</h2>

          <p>
            ${escapeHtml(code)}
          </p>

          <img
            src="${data.data}"
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
        `
      );

      popup.document.close();

    } catch (error) {

      alert(
        error.message
      );
    }
  };


/* -----------------------------
   VERIFY PRODUCT
----------------------------- */

$("verifyForm")
  .addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      const code =
        $("verifyCode")
          .value
          .trim()
          .toUpperCase();

      if (!code) {
        return;
      }

      const resultBox =
        $("verifyResult");

      resultBox.innerHTML =
        `
        <div class="verification-loading">
          Checking product...
        </div>
        `;

      try {

        const data =
          await api(
            "/api/verify/" +
            encodeURIComponent(
              code
            )
          );

        renderVerificationResult(
          data
        );

      } catch (error) {

        resultBox.innerHTML =
          `
          <div class="verification-error">
            ${escapeHtml(
              error.message
            )}
          </div>
          `;
      }
    }
  );


/* -----------------------------
   VERIFICATION RESULT
----------------------------- */

function renderVerificationResult(
  data
) {

  const resultBox =
    $("verifyResult");

  if (
    data.result ===
    "not_verified"
  ) {

    resultBox.innerHTML =
      `
      <div class="verification-result not-verified">

        <h3>
          ✕ NOT VERIFIED
        </h3>

        <p>
          ${escapeHtml(
            data.message
          )}
        </p>

      </div>
      `;

    return;
  }


  const product =
    data.product;

  let title =
    "✓ VERIFIED";

  if (
    data.result ===
    "warning"
  ) {
    title =
      "⚠ WARNING";
  }


  const imageHtml =
    product?.imageData
      ? `
        <div class="verified-product-image">
          <img
            src="${product.imageData}"
            alt="Registered product"
          >
        </div>
        `
      : `
        <div class="verified-product-no-image">
          No product image registered
        </div>
        `;


  resultBox.innerHTML =
    `
    <div
      class="verification-result ${escapeHtml(
        data.result
      )}"
    >

      <h3>
        ${title}
      </h3>


      ${imageHtml}


      <div class="verified-product-details">

        <h4>
          ${escapeHtml(
            product.productName
          )}
        </h4>

        <p>
          <strong>Brand:</strong>
          ${escapeHtml(
            product.brand
          )}
        </p>

        <p>
          <strong>Batch:</strong>
          ${escapeHtml(
            product.batch || "—"
          )}
        </p>

        <p>
          <strong>Verification code:</strong>
          <code>
            ${escapeHtml(
              product.code
            )}
          </code>
        </p>

        <p>
          ${escapeHtml(
            data.message
          )}
        </p>

      </div>

    </div>
    `;
}


/* -----------------------------
   AUTO VERIFY FROM QR URL
----------------------------- */

function autoVerifyFromUrl() {

  const params =
    new URLSearchParams(
      window.location.search
    );

  const code =
    params.get("verify");

  if (!code) {
    return;
  }

  $("verifyCode")
    .value =
    code;

  $("verifyForm")
    .dispatchEvent(
      new Event(
        "submit",
        {
          bubbles: true,
          cancelable: true
        }
      )
    );

  const verifySection =
    $("verify");

  if (verifySection) {

    verifySection.scrollIntoView({
      behavior: "smooth"
    });
  }
}


/* -----------------------------
   REFRESH
----------------------------- */

$("refreshProducts")
  .addEventListener(
    "click",
    loadDashboard
  );


/* -----------------------------
   HTML ESCAPING
----------------------------- */

function escapeHtml(
  value
) {

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


function escapeJs(
  value
) {

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
    );
}


/* -----------------------------
   START
----------------------------- */

loadCurrentUser();

autoVerifyFromUrl();
