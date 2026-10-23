# library.go.iam

Cliente Go del servicio de permisos [`backend.k8s.iam`](https://github.com/MirandaSpa/backend.k8s.iam) (ERM-807). Sirve para preguntar "¿puede este usuario hacer X en la sucursal Y?", "¿quién puede?" y para proteger rutas HTTP con un permiso.

- Solo usa la librería estándar (el adaptador `ginmw` usa `gin`, que ya usan los servicios antiguos).
- **No tiene caché**: cada llamada consulta a `iam`. Si `iam` no responde, `Can` devuelve error (nunca `false`): quien llama decide qué hacer.
- Los errores no incluyen el cuerpo de la respuesta ni datos personales; los logs llevan solo IDs internos.
- Requiere la versión más reciente de Go: la regla de la organización es compilar siempre con la última versión estable.

## Instalación

```bash
go get github.com/MirandaSpa/library.go.iam@vX.Y.Z   # el repo es privado: GOPRIVATE=github.com/MirandaSpa/*
```

## Uso

```go
c, err := iam.New("http://iam.dev.svc.cluster.local:8080/api/v2/iam") // IAM_URL, sin /internal

ok, err := c.Can(ctx, userID, "sales:discount:authorize", branchID) // bool + error
users, err := c.Holders(ctx, "sales:discount:authorize", branchID)  // IDs internos de usuario
```

### Proteger una ruta

```go
mode, _ := iam.ParseMode(os.Getenv("IAM_MODE")) // "" = strict
guard := iam.NewGuard(c, mode)

// net/http
mux.Handle("/log", guard.RequirePermission("storage:storing:create")(handler))

// gin
r.POST("/log", ginmw.RequirePermission(guard, "storage:storing:create"), handler)
```

El guard toma el usuario de `X-Usuario-Id` y la sucursal de `X-Sucursal-Id`, y responde:

| Situación | Respuesta (modo `strict`) |
|---|---|
| Sin `X-Usuario-Id` | 401 |
| El permiso no está asignado | 403 |
| `iam` no pudo responder | 503 |
| Permitido | continúa |

En modo `shadow` **nunca rechaza**: registra "iam guard: denied ..." y deja pasar. Es la forma de adoptar el guard sin que nadie pierda acceso; se pasa a `strict` cuando el registro no muestra denegaciones inesperadas.

> **Importante:** `X-Usuario-Id` solo es confiable si lo fija el Ingress con el autorizador de `iam` (`auth-url` + `auth-response-headers`). Mientras el servicio no esté detrás de ese `auth-url`, el cliente puede falsificarlo; adopta el guard en `shadow` hasta entonces.

## Desarrollo

| Comando | Qué hace |
|---|---|
| `make test` | Tests con `-race` |
| `make cover` | Tests + umbral de cobertura (70 %) |
| `make lint` | `golangci-lint` |
| `make check` | Todo lo que corre el CI |

Se versiona con tags `vX.Y.Z` (en sprint, `-beta.N`); no publica imagen.
