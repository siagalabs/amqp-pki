"use strict";

const rhea = require("rhea");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node consume-decrypt.js [options]

Consumes messages from an AMQP 1.0 queue and decrypts payloads that were
encrypted with hybrid encryption (AES-256-GCM + RSA-OAEP). The consumer's
private key is used to unwrap the AES session key.

Options:
  --host <hostname>         AMQP broker hostname            (default: localhost)
  --port <port>             AMQP broker port                (default: 5671)
  --vhost <vhost>           RabbitMQ virtual host            (default: /)
  --queue <address>         Queue / address name            (default: example-queue)
  --ca <path>               CA certificate file             (default: certs/ca.pem)
  --cert <path>             Client certificate file         (default: certs/client-cert.pem)
  --key <path>              Client private key file         (default: certs/client-key.pem)
  --decrypt-key <path>      Private key for decryption      (defaults to --key value)
  --help                    Show this help message
`);
}

function parseArgs (argv) {
  const args = argv.slice(2);
  const config = {
    host: "localhost",
    port: 5671,
    vhost: "/",
    queue: "example-queue",
    ca: path.join(__dirname, "certs", "ca.pem"),
    cert: path.join(__dirname, "certs", "client-cert.pem"),
    key: path.join(__dirname, "certs", "client-key.pem"),
    decryptKey: null, // will fall back to `key` if not set
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--host":
        config.host = args[++i];
        break;
      case "--port":
        config.port = parseInt(args[++i], 10);
        break;
      case "--vhost":
        config.vhost = args[++i];
        break;
      case "--queue":
        config.queue = args[++i];
        break;
      case "--ca":
        config.ca = args[++i];
        break;
      case "--cert":
        config.cert = args[++i];
        break;
      case "--key":
        config.key = args[++i];
        break;
      case "--decrypt-key":
        config.decryptKey = args[++i];
        break;
      case "--help":
      case "-h":
        printUsage();
        process.exit(0);
        break;
      default:
        console.error(`Unknown option: ${args[i]}`);
        printUsage();
        process.exit(1);
    }
  }

  if (!config.decryptKey) {
    config.decryptKey = config.key;
  }

  return config;
}

const config = parseArgs(process.argv);

// ── Load TLS certificates ──────────────────────────────────────────────────
function loadCertificates () {
  try {
    return {
      ca: [fs.readFileSync(config.ca)],
      cert: fs.readFileSync(config.cert),
      key: fs.readFileSync(config.key),
      enable_sasl_external: true,
      rejectUnauthorized: true,
    };
  } catch (err) {
    console.error("Failed to load TLS certificates:", err.message);
    process.exit(1);
  }
}

// ── Decryption helpers ──────────────────────────────────────────────────────
function loadDecryptionKey () {
  try {
    return fs.readFileSync(config.decryptKey);
  } catch (err) {
    console.error("Failed to load decryption key:", err.message);
    process.exit(1);
  }
}

/**
 * Decrypt a message that was encrypted with hybrid encryption.
 *
 * 1. RSA-decrypt the AES session key using the recipient's private key.
 * 2. Decrypt the ciphertext with AES-256-GCM using the recovered key, IV,
 *    and authentication tag.
 *
 * @param {string} ciphertext64   – base64-encoded AES-GCM ciphertext
 * @param {string} encryptedKey64 – base64-encoded RSA-encrypted AES key
 * @param {string} iv64           – base64-encoded 96-bit IV
 * @param {string} authTag64      – base64-encoded GCM authentication tag
 * @param {Buffer} privateKeyPem  – PEM-encoded RSA private key
 * @returns {string} the decrypted plaintext
 */
function decryptPayload (ciphertext64, encryptedKey64, iv64, authTag64, privateKeyPem) {
  // 1 – Unwrap the AES key with RSA-OAEP
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encryptedKey64, "base64"),
  );

  // 2 – Decrypt with AES-256-GCM
  const iv = Buffer.from(iv64, "base64");
  const authTag = Buffer.from(authTag64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertext64, "base64", "utf8");
  plaintext += decipher.final("utf8");

  return plaintext;
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();
  const privateKey = loadDecryptionKey();
  const container = rhea.create_container();

  let messageCount = 0;

  // ── Connection events ─────────────────────────────────────────────────────
  container.on("connection_open", (context) => {
    console.log("[connected] AMQP connection established via mTLS");
    console.log(`[listening] Waiting for messages on "${config.queue}" …\n`);
    context.connection.open_receiver(config.queue);
  });

  container.on("connection_close", () => {
    console.log("[disconnected] AMQP connection closed");
  });

  container.on("connection_error", (context) => {
    const err = context.connection.error || context.error;
    console.error("[connection_error]", err ? err.message || err : "unknown");
  });

  // ── Receiver events ──────────────────────────────────────────────────────
  container.on("message", (context) => {
    messageCount++;
    const msg = context.message;
    const props = msg.application_properties || {};
    const body = typeof msg.body === "string" ? msg.body : JSON.stringify(msg.body);

    console.log(`── message #${messageCount} ──────────────────────────────────`);

    const isEncrypted = props["x-encrypted"] === "true";

    if (!isEncrypted) {
      console.log("[received] (unencrypted) payload:", body);
      console.log();
      return;
    }

    const encryptedKey = props["x-encrypted-key"];
    const iv = props["x-encryption-iv"];
    const authTag = props["x-encryption-tag"];
    const algorithm = props["x-encryption-algorithm"];

    console.log("[received] algorithm:", algorithm);
    console.log("[received] ciphertext:", body);
    console.log("[received] encrypted AES key:", encryptedKey);
    console.log("[received] iv:", iv);
    console.log("[received] authTag:", authTag);

    try {
      const plaintext = decryptPayload(body, encryptedKey, iv, authTag, privateKey);
      console.log("[decrypt]  ✔  plaintext:", plaintext);
    } catch (err) {
      console.error("[decrypt]  ✘  Decryption failed:", err.message);
    }

    console.log();
  });

  // ── Disconnection / error handling ────────────────────────────────────────
  container.on("disconnected", (context) => {
    const err = context.error;
    if (err) {
      console.error("[disconnected]", err.message || err);
    }
  });

  container.on("error", (err) => {
    console.error("[error]", err);
  });

  // ── Graceful shutdown on SIGINT ───────────────────────────────────────────
  process.on("SIGINT", () => {
    console.log("\n[shutdown] Received SIGINT, closing connection …");
    container.connections && container.connections.forEach((c) => c.close());
    setTimeout(() => process.exit(0), 500);
  });

  // ── Establish the mTLS connection to RabbitMQ ─────────────────────────────
  console.log(`Connecting to amqps://${config.host}:${config.port}/${encodeURIComponent(config.vhost)} using mTLS (EXTERNAL) …`);

  container.connect({
    host: config.host,
    port: config.port,
    transport: "tls",
    hostname: config.vhost,
    servername: config.host,
    ...tlsOptions,
  });
}

main();
