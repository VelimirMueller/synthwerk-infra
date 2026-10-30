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

// Page builder database (synthwerk#107): the password from the file studio-db-secret wrote,
// put into BUILDER_DATABASE_URL_BASE. A NUXT_BUILDER_DATABASE_URL in the env wins. No file:
// studio starts, /api/builder answers 503 builder_not_configured.
const builderBase = process.env.BUILDER_DATABASE_URL_BASE
const builderPasswordFile = process.env.BUILDER_DATABASE_PASSWORD_FILE
if (builderBase && builderPasswordFile && !process.env.NUXT_BUILDER_DATABASE_URL) {
  let password = ''
  try {
    password = readFileSync(builderPasswordFile, 'utf8').trim()
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error(`studio: cannot read the builder database password from ${builderPasswordFile}: ${err.code ?? err.name}`)
      process.exit(1)
    }
  }
  if (password) {
    let url
    try {
      url = new URL(builderBase)
    } catch {
      console.error('studio: BUILDER_DATABASE_URL_BASE is not a URL')
      process.exit(1)
    }
    url.password = encodeURIComponent(password)
    process.env.NUXT_BUILDER_DATABASE_URL = url.toString()
  }
}

if (process.argv[2] === 'builder-db-check') {
  // Stack test: connect with the URL built above and name the role and the database.
  // Prints no URL and no password.
  const { createRequire } = await import('node:module')
  const pg = createRequire('/app/.output/server/index.mjs')('pg')
  const client = new pg.Client({ connectionString: process.env.NUXT_BUILDER_DATABASE_URL })
  try {
    await client.connect()
    const { rows } = await client.query(
      "select current_user as role, current_database() as db, has_schema_privilege('public', 'CREATE') as can_create"
    )
    console.log(JSON.stringify(rows[0]))
  } catch (err) {
    console.log(JSON.stringify({ error: err.code ?? err.name }))
    process.exitCode = 1
  } finally {
    await client.end().catch(() => {})
  }
  process.exit()
}

if (process.argv[2] === 'healthcheck') {
  // Container health check: the server answers on its port.
  const res = await fetch(`http://127.0.0.1:${process.env.PORT ?? 3000}/api/auth/session`)
  process.exit(res.status < 500 ? 0 : 1)
}

await import('./.output/server/index.mjs')
