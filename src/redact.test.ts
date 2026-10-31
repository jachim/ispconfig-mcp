import { test } from "node:test";
import assert from "node:assert/strict";
import { REDACTED, dropRedacted, redactSecrets } from "./redact.js";

test("masks secret fields of a web domain record", () => {
  const site = {
    domain_id: "22",
    domain: "example.itur.pl",
    ssl_key: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
    ssl_request: "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
    ssl_cert: "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----",
    stats_password: "x",
    backup_password: "",
    nginx_directives: "location / {}",
  };
  const out = redactSecrets(site);
  assert.equal(out.ssl_key, REDACTED);
  assert.equal(out.ssl_request, REDACTED);
  assert.equal(out.stats_password, REDACTED);
  assert.equal(out.backup_password, "", "empty values stay empty, so 'not set' is still visible");
  assert.equal(out.ssl_cert, site.ssl_cert, "the public certificate is not a secret");
  assert.equal(out.nginx_directives, site.nginx_directives);
  assert.match(site.ssl_key, /PRIVATE KEY/, "the input is not modified");
});

test("masks nested and listed records (mail users, DKIM, clients, tokens)", () => {
  const out = redactSecrets({
    domain: { dkim_private: "key", dkim_public: "pub" },
    users: [{ email: "a@b.pl", password: "$6$hash" }, { email: "c@d.pl", password: null }],
    client: { username: "c1", passwort: "x", database_password: "y", api_token: "t", client_secret: "s" },
  });
  assert.equal(out.domain.dkim_private, REDACTED);
  assert.equal(out.domain.dkim_public, "pub");
  assert.equal(out.users[0].password, REDACTED);
  assert.equal(out.users[0].email, "a@b.pl");
  assert.equal(out.users[1].password, null);
  assert.equal(out.client.passwort, REDACTED);
  assert.equal(out.client.database_password, REDACTED);
  assert.equal(out.client.api_token, REDACTED);
  assert.equal(out.client.client_secret, REDACTED);
  assert.equal(out.client.username, "c1");
});

test("scalars and non-secret structures pass through", () => {
  assert.equal(redactSecrets(42), 42);
  assert.equal(redactSecrets("text"), "text");
  assert.equal(redactSecrets(null), null);
  assert.deepEqual(redactSecrets([1, { a: 2 }]), [1, { a: 2 }]);
});

test("placeholders are never sent back to ISPConfig", () => {
  const params = {
    client_id: 0,
    primary_id: 22,
    params: { ssl_key: REDACTED, password: REDACTED, nginx_directives: "include x;", list: [REDACTED, "a"] },
  };
  assert.deepEqual(dropRedacted(params), {
    client_id: 0,
    primary_id: 22,
    params: { nginx_directives: "include x;", list: ["a"] },
  });
});
