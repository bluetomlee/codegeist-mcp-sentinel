// Offline manifest validation using the @forge/manifest schema bundled with @forge/api.
// No login / network required.
const path = require('node:path');
const { validate } = require('@forge/manifest');

validate(false, path.resolve(__dirname, '..', 'manifest.yml')).then((r) => {
  for (const e of r.errors ?? []) console.log(`${e.level}: ${e.message}`);
  console.log(r.success ? 'manifest.yml is valid' : 'manifest.yml is INVALID');
  process.exit(r.success ? 0 : 1);
});
