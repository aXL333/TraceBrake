# TraceBrake website scaffold

The static landing page lives in this `docs` directory so it can be hosted without a build step or paid service.

## Preview locally

From the repository root:

```powershell
python -m http.server 8080 --directory docs
```

Then open <http://localhost:8080/>.

## Deployment options

- **GitHub Pages:** publish from the `main` branch and `/docs` directory.
- **Cloudflare Pages:** use `docs` as the build output directory; no build command is required.
- **Any static host:** upload the contents of `docs` while retaining the `assets` directory.

The public rename from **Foreman Agent Safety** to **TraceBrake** is live. Before publishing a new release, update:

1. GitHub repository/release links if their canonical URL changes.
2. The Open Graph image, which still uses the original Foreman social preview.
3. Screenshots as refreshed TraceBrake-branded captures become available.

No analytics, cookies, external fonts, form backend or third-party JavaScript are included.
