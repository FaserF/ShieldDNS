package main

import _ "embed"

//go:embed www/admin/assets/cloudflare_worker_template.js
var CloudflareWorkerScriptTemplate string
