// Start the studio server with the OIDC client the Zitadel bootstrap wrote
// (STUDIO_CLIENT_FILE, JSON: project_id, client_id, client_secret). Values set in
// the environment win. Prints no value.
import { readFileSync } from 'node:fs'

const file = process.env.STUDIO_CLIENT_FILE
if (file) {
  let client
  try {
    client = JSON.parse(readFileSync(file, 'utf8'))
  } catch (err) {
    // The message names the file and the cause, never its content.
    console.error(`studio: cannot read the OIDC client from ${file} (run zitadel-bootstrap first): ${err.code ?? err.name}`)
    process.exit(1)
  }
  process.env.NUXT_OIDC_CLIENT_ID ||= client.client_id ?? ''
  process.env.NUXT_OIDC_CLIENT_SECRET ||= client.client_secret ?? ''
  process.env.NUXT_OIDC_PROJECT_ID ||= client.project_id ?? ''
}

// Service token of the vision label admin (synthwerk#44), from the file vision-admin-token
// wrote. No file (profile vision off): studio starts, /api/labels answers 503.
const visionTokenFile = process.env.VISION_ADMIN_TOKEN_FILE
if (visionTokenFile && !process.env.NUXT_VISION_ADMIN_TOKEN) {
  try {
    const token = readFileSync(visionTokenFile, 'utf8').trim()
    // Empty file: leave the variable unset, so /api/labels answers 503 and names it.
    if (token) process.env.NUXT_VISION_ADMIN_TOKEN = token
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error(`studio: cannot read the vision admin token from ${visionTokenFile}: ${err.code ?? err.name}`)
      process.exit(1)
    }
  }
}

if (process.argv[2] === 'healthcheck') {
  // Container health check: the server answers on its port.
  const res = await fetch(`http://127.0.0.1:${process.env.PORT ?? 3000}/api/auth/session`)
  process.exit(res.status < 500 ? 0 : 1)
}

await import('./.output/server/index.mjs')
