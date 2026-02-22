"use strict";

const rhea = require("rhea");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node send-signed.js [options]

Options:
  --host <hostname>       AMQP broker hostname            (default: localhost)
  --port <port>           AMQP broker port                (default: 5671)
  --vhost <vhost>         RabbitMQ virtual host            (default: /)
  --queue <address>       Queue / address name            (default: example-queue)
  --ca <path>             CA certificate file             (default: certs/ca.pem)
  --cert <path>           Client certificate file         (default: certs/client-cert.pem)
  --key <path>            Client private key file         (default: certs/client-key.pem)
  --signing-key <path>    Private key used for signing    (defaults to --key value)
  --algorithm <alg>       Signature algorithm             (default: SHA256)
  --payload <text>        Message payload to send         (default: "Hello from mTLS AMQP client!")
  --help                  Show this help message
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
    signingKey: null,          // will fall back to `key` if not set
    algorithm: "SHA256",
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
      case "--signing-key":
        config.signingKey = args[++i];
        break;
      case "--algorithm":
        config.algorithm = args[++i];
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

  // Default signingKey to the mTLS client key
  if (!config.signingKey) {
    config.signingKey = config.key;
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

// ── Digital signature helpers ───────────────────────────────────────────────
function loadSigningKey () {
  try {
    return fs.readFileSync(config.signingKey);
  } catch (err) {
    console.error("Failed to load signing key:", err.message);
    process.exit(1);
  }
}

/**
 * Sign a payload string and return a base64-encoded signature.
 */
function signPayload (payload, privateKey, algorithm) {
  const sign = crypto.createSign(algorithm);
  sign.update(payload);
  sign.end();
  return sign.sign(privateKey, "base64");
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();
  const privateKey = loadSigningKey();
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
    const payload = config.payload;
    const signature = signPayload(payload, privateKey, config.algorithm);

    const message = {
      body: payload,
      application_properties: {
        "x-signature": signature,
        "x-signature-algorithm": config.algorithm,
      },
    };

    context.sender.send(message);
    console.log("[sent] payload:", JSON.stringify(payload));
    console.log("[sent] x-signature:", signature);
    console.log("[sent] x-signature-algorithm:", config.algorithm);
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
