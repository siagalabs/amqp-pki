"use strict";

const rhea = require("rhea");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node consume-verify.js [options]

Options:
  --host <hostname>         AMQP broker hostname            (default: localhost)
  --port <port>             AMQP broker port                (default: 5671)
  --vhost <vhost>           RabbitMQ virtual host            (default: /)
  --queue <address>         Queue / address name            (default: example-queue)
  --ca <path>               CA certificate file             (default: certs/ca.pem)
  --cert <path>             Client certificate file         (default: certs/client-cert.pem)
  --key <path>              Client private key file         (default: certs/client-key.pem)
  --sender-cert <path>      Sender's certificate / public key for signature verification
                            (defaults to --cert value)
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
    senderCert: null, // will fall back to `cert` if not set
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
      case "--sender-cert":
        config.senderCert = args[++i];
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

  if (!config.senderCert) {
    config.senderCert = config.cert;
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

// ── Signature verification ──────────────────────────────────────────────────
function loadSenderPublicKey () {
  try {
    return fs.readFileSync(config.senderCert);
  } catch (err) {
    console.error("Failed to load sender certificate for verification:", err.message);
    process.exit(1);
  }
}

/**
 * Verify a base64-encoded signature against the payload using the sender's
 * public key (or certificate).
 *
 * @param {string} payload     – the original message body
 * @param {string} signature   – base64-encoded signature
 * @param {string} algorithm   – e.g. "SHA256"
 * @param {Buffer} publicKey   – PEM-encoded certificate or public key
 * @returns {boolean}
 */
function verifySignature (payload, signature, algorithm, publicKey) {
  const verify = crypto.createVerify(algorithm);
  verify.update(payload);
  verify.end();
  return verify.verify(publicKey, signature, "base64");
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();
  const senderPublicKey = loadSenderPublicKey();
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
    console.log("[received] payload:", body);

    const signature = props["x-signature"];
    const algorithm = props["x-signature-algorithm"];

    if (!signature || !algorithm) {
      console.warn("[verify]  ⚠  No signature found in application_properties — skipping verification");
      console.log();
      return;
    }

    console.log("[verify]  algorithm:", algorithm);
    console.log("[verify]  signature:", signature);

    try {
      const valid = verifySignature(body, signature, algorithm, senderPublicKey);
      if (valid) {
        console.log("[verify]  ✔  Signature is VALID");
      } else {
        console.error("[verify]  ✘  Signature is INVALID");
      }
    } catch (err) {
      console.error("[verify]  ✘  Verification failed:", err.message);
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
