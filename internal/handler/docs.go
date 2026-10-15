package handler

import (
	"net/http"

	"github.com/TonnPcst/martgo-auth/api"
)

// Swagger UI has no dark theme, so dark mode inverts the page colors and
// re-inverts code blocks and images. The choice is kept in localStorage and
// defaults to the OS setting.
const swaggerUIPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>martgo auth API docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"
      integrity="sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn" crossorigin="anonymous">
  <script>
    (function () {
      var saved = null;
      try { saved = localStorage.getItem("docs-theme"); } catch (e) {}
      var dark = saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
      document.documentElement.dataset.theme = dark ? "dark" : "light";
    })();
  </script>
  <style>
    body { margin: 0; background: #fff; transition: background .2s; }
    html[data-theme="dark"] body { background: #1c1c1c; }
    html[data-theme="dark"] .swagger-ui { filter: invert(88%) hue-rotate(180deg); }
    html[data-theme="dark"] .swagger-ui .microlight,
    html[data-theme="dark"] .swagger-ui img { filter: invert(100%) hue-rotate(180deg); }
    #theme-toggle {
      position: fixed; top: 12px; right: 16px; z-index: 1000;
      padding: 6px 12px; border-radius: 6px; cursor: pointer;
      font: 600 13px sans-serif; border: 1px solid #888;
      background: #fff; color: #222;
    }
    html[data-theme="dark"] #theme-toggle { background: #2b2b2b; color: #eee; border-color: #555; }
  </style>
</head>
<body>
  <button id="theme-toggle" type="button"></button>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
      integrity="sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep" crossorigin="anonymous"></script>
  <script>
    var toggle = document.getElementById("theme-toggle");
    function label() {
      toggle.textContent = document.documentElement.dataset.theme === "dark" ? "☀ Light" : "☾ Dark";
    }
    toggle.addEventListener("click", function () {
      var next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("docs-theme", next); } catch (e) {}
      label();
    });
    label();

    window.ui = SwaggerUIBundle({
      url: "/docs/openapi.yaml",
      dom_id: "#swagger-ui",
      persistAuthorization: true,
    });
  </script>
</body>
</html>`

// swaggerUI serves the Swagger UI page. GET /docs
//
// ENG: Returns the static HTML page that loads Swagger UI from the CDN and points it
// at /docs/openapi.yaml. Only registered when docs are enabled.
// LAO: ສົ່ງໜ້າ HTML ຂອງ Swagger UI ສຳລັບເບິ່ງເອກະສານ API.
//
// @param w - response writer
// @returns writes 200 with the HTML page
func swaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerUIPage))
}

// openAPISpec serves the embedded OpenAPI spec. GET /docs/openapi.yaml
//
// ENG: Writes the api/openapi.yaml file that is embedded in the binary.
// LAO: ສົ່ງໄຟລ໌ OpenAPI spec (YAML) ທີ່ embed ໄວ້ໃນ binary.
//
// @param w - response writer
// @returns writes 200 with the YAML spec
func openAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(api.OpenAPISpec)
}
