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

## Registrar el manifiesto del servicio

Cada servicio declara sus permisos y sus rutas en un `permissions.yaml` en la raíz de su repo y los registra en `iam` al arrancar. Así `iam` sabe qué permiso exige cada ruta (para el `auth-url` del Ingress y para el legacy), sin cargas manuales. Registrar un manifiesto no da permisos a nadie: solo agrega al catálogo, y las rutas del servicio se reemplazan en cada registro.

```yaml
service: products            # nombre del servicio (identifica sus rutas en iam)
permissions:
  - id: products:product:list      # area:recurso:accion, en inglés y minúsculas; el área puede agrupar varios servicios
    label: Ver productos           # lo que lee quien administra
    description: Permite ver la lista de productos.
    scope: global                  # branch (por defecto) | global
    audit: denied                  # denied (por defecto) | always
    kind: entry                    # entry (por defecto) | internal
routes:
  - method: GET
    path: /api/v2/internal_product/products     # ruta completa; {id} para lo que varía
    permission: products:product:list
  - method: GET
    path: /api/v2/internal_product/products/test
    public: true                                # cualquier token válido, sin permiso
```

Al arrancar el servicio:

```go
manifest, err := manifestfile.Load("permissions.yaml") // github.com/MirandaSpa/library.go.iam/manifestfile
if err != nil { log.Fatal(err) }                       // un manifiesto inválido es un error de programación
client, _ := iam.New(os.Getenv("IAM_URL"))
_, _ = client.RegisterInBackground(ctx, manifest, log.Printf) // no frena el arranque; reintenta hasta que iam responda
```

`RegisterInBackground` reintenta con espera creciente (de 1 a 30 segundos) hasta que `iam` responde o `ctx` termina. El archivo se empaqueta en la imagen (en el `Dockerfile`, copiar `permissions.yaml` junto al binario).

### Test de CI: que el manifiesto no se desalinee del código

```go
func TestManifestMatchesRoutes(t *testing.T) {
	manifest, err := manifestfile.Load("permissions.yaml")
	require.NoError(t, err)
	engine := setupRouter() // el mismo router que usa el servicio
	problems := iam.CheckRoutes(manifest, ginmw.Routes(engine), iam.RouteKey{Method: "GET", Path: "/healthz"})
	assert.Empty(t, problems)
}
```

Falla si el servicio sirve una ruta que el manifiesto no declara, o si el manifiesto declara una ruta que el servicio no sirve. Los parámetros se comparan por posición (`:id` de gin y `{id}` del manifiesto son el mismo segmento). `manifestfile` es un paquete aparte porque necesita una librería de YAML (`go.yaml.in/yaml/v3`, de la organización oficial `yaml`); el paquete `iam` sigue usando solo la biblioteca estándar.

## Desarrollo

| Comando | Qué hace |
|---|---|
| `make test` | Tests con `-race` |
| `make cover` | Tests + umbral de cobertura (70 %) |
| `make lint` | `golangci-lint` |
| `make check` | Todo lo que corre el CI |

Se versiona con tags `vX.Y.Z` (en sprint, `-beta.N`); no publica imagen.
