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
localStorage.getItem(
"verifyit_token"
);

const headers = {
...(options.headers || {})
};

if (
options.body &&
typeof options.body !== "string"
) {

```
headers["Content-Type"] =
  "application/json";

options.body =
  JSON.stringify(
    options.body
  );
```

}

if (token) {

```
headers.Authorization =
  `Bearer ${token}`;
```

}

const response =
await fetch(
url,
{
...options,
headers
}
);

let data = {};

try {

```
data =
  await response.json();
```

} catch {

```
data = {};
```

}

if (!response.ok) {

```
/*
  Important:
  If VerifyIt is under lockdown,
  do NOT delete the user's token.
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
```

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
(
resolve,
reject
) => {

```
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

  reader.readAsDataURL(
    file
  );
}
```

);
}

/* -----------------------------
AUTH DISPLAY
----------------------------- */

function showDashboard(
business
) {

if ($("authArea")) {

```
$("authArea").hidden =
  true;
```

}

if ($("dashboard")) {

```
$("dashboard").hidden =
  false;
```

}

if ($("businessName")) {

```
$("businessName")
  .textContent =
  business?.name ||
  "Business Dashboard";
```

}

if ($("businessEmail")) {

```
$("businessEmail")
  .textContent =
  business?.email ||
  "";
```

}

loadDashboard();
}

function showAuth() {

if ($("authArea")) {

```
$("authArea").hidden =
  false;
```

}

if ($("dashboard")) {

```
$("dashboard").hidden =
  true;
```

}
}

/* -----------------------------
CURRENT USER
----------------------------- */

async function loadCurrentUser() {

const token =
localStorage.getItem(
"verifyit_token"
);

if (!token) {

```
showAuth();

return;
```

}

try {

```
const business =
  await api(
    "/api/me"
  );

showDashboard(
  business
);
```

} catch (error) {

```
/*
  A lockdown is NOT an invalid
  login session.

  Keep the token if the server
  says the system is locked.
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
```

}
}

/* -----------------------------
REGISTER
----------------------------- */

if ($("registerForm")) {

$("registerForm")
.addEventListener(
"submit",
async event => {

```
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
```

}

/* -----------------------------
LOGIN
----------------------------- */

if ($("loginForm")) {

$("loginForm")
.addEventListener(
"submit",
