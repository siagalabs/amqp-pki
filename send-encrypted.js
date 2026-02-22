"use strict";

const rhea = require("rhea");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node send-encrypted.js [options]

Encrypts the payload using hybrid encryption (AES-256-GCM + RSA) and sends it
over AMQP 1.0 via mTLS. The recipient's public key / certificate is used to
encrypt the AES session key so only the holder of the corresponding private key
can decrypt the message.

Options:
  --host <hostname>         AMQP broker hostname            (default: localhost)
  --port <port>             AMQP broker port                (default: 5671)
  --vhost <vhost>           RabbitMQ virtual host            (default: /)
  --queue <address>         Queue / address name            (default: example-queue)
  --ca <path>               CA certificate file             (default: certs/ca.pem)
  --cert <path>             Client certificate file         (default: certs/client-cert.pem)
  --key <path>              Client private key file         (default: certs/client-key.pem)
  --recipient-cert <path>   Recipient's cert / public key for encrypting
                            (defaults to --cert value)
  --payload <text>          Message payload to send         (default: "Hello from mTLS AMQP client!")
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
    recipientCert: null, // will fall back to `cert` if not set
    payload: "Hello from mTLS AMQP client!",
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
      case "--recipient-cert":
        config.recipientCert = args[++i];
        break;
      case "--payload":
        config.payload = args[++i];
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

  if (!config.recipientCert) {
    config.recipientCert = config.cert;
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

// ── Hybrid encryption (AES-256-GCM + RSA-OAEP) ─────────────────────────────
function loadRecipientPublicKey () {
  try {
    return fs.readFileSync(config.recipientCert);
  } catch (err) {
    console.error("Failed to load recipient certificate:", err.message);
    process.exit(1);
  }
}

/**
 * Encrypt a plaintext payload using hybrid encryption.
 *
 * 1. Generate a random 256-bit AES key and 96-bit IV.
 * 2. Encrypt the plaintext with AES-256-GCM  → ciphertext + authTag.
 * 3. Encrypt the AES key with the recipient's RSA public key (OAEP + SHA-256).
 *
 * All binary values are returned as base64 strings.
 */
function encryptPayload (plaintext, recipientPem) {
  // AES-256-GCM session key
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  let ciphertext = cipher.update(plaintext, "utf8", "base64");
  ciphertext += cipher.final("base64");
  const authTag = cipher.getAuthTag().toString("base64");

  // RSA-encrypt the AES key with the recipient's public key
  const encryptedKey = crypto.publicEncrypt(
    {
      key: recipientPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  ).toString("base64");

  return { ciphertext, iv: iv.toString("base64"), authTag, encryptedKey };
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();
  const recipientPem = loadRecipientPublicKey();
  const container = rhea.create_container();

  // ── Connection events ─────────────────────────────────────────────────────
  container.on("connection_open", (context) => {
    console.log("[connected] AMQP connection established via mTLS");
    context.connection.open_sender(config.queue);
  });

  container.on("connection_close", () => {
    console.log("[disconnected] AMQP connection closed");
  });

  container.on("connection_error", (context) => {
    const err = context.connection.error || context.error;
    console.error("[connection_error]", err ? err.message || err : "unknown");
  });

  // ── Sender events ────────────────────────────────────────────────────────
  container.on("sendable", (context) => {
    const plaintext = config.payload;
    const encrypted = encryptPayload(plaintext, recipientPem);

    const message = {
      // The body is the AES-GCM ciphertext (base64)
      body: encrypted.ciphertext,
      application_properties: {
        "x-encrypted": "true",
        "x-encryption-algorithm": "aes-256-gcm+rsa-oaep-sha256",
        "x-encrypted-key": encrypted.encryptedKey,
        "x-encryption-iv": encrypted.iv,
        "x-encryption-tag": encrypted.authTag,
      },
    };

    context.sender.send(message);
    console.log("[sent] plaintext:", JSON.stringify(plaintext));
    console.log("[sent] ciphertext:", encrypted.ciphertext);
    console.log("[sent] encrypted AES key:", encrypted.encryptedKey);
    console.log("[sent] iv:", encrypted.iv);
    console.log("[sent] authTag:", encrypted.authTag);
    context.sender.close();
  });

  container.on("accepted", () => {
    console.log("[accepted] Message was accepted by the broker");
  });

  container.on("rejected", (_context) => {
    console.error("[rejected] Message was rejected by the broker");
  });

  // ── Disconnection / error handling ────────────────────────────────────────
  container.on("sender_close", (context) => {
    context.connection.close();
  });

  container.on("disconnected", (context) => {
    const err = context.error;
    if (err) {
      console.error("[disconnected]", err.message || err);
    }
  });

  container.on("error", (err) => {
    console.error("[error]", err);
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
