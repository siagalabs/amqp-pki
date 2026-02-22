"use strict";

const rhea = require("rhea");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node send.js [options]

Sends a message over AMQP 1.0 via mTLS to RabbitMQ.
Use --sign and/or --encrypt switches to enable digital signature and encryption.

Options:
  --config <path>           Load options from a JSON config file
  --host <hostname>         AMQP broker hostname            (default: localhost)
  --port <port>             AMQP broker port                (default: 5671)
  --vhost <vhost>           RabbitMQ virtual host            (default: /)
  --queue <address>         Queue / address name            (default: example-queue)
  --ca <path>               CA certificate file             (default: certs/ca.pem)
  --cert <path>             Client certificate file         (default: certs/client-cert.pem)
  --key <path>              Client private key file         (default: certs/client-key.pem)
  --payload <text>          Message payload                 (default: "Hello from mTLS AMQP client!")
  --payload-file <path>     Load message payload from a file (overrides --payload)
  --count <n>               Number of messages to send       (default: 1)

Feature switches:
  --sign                    Enable digital signature on the payload
  --encrypt                 Enable hybrid encryption (AES-256-GCM + RSA-OAEP)

Signing options (used when --sign is enabled):
  --signing-key <path>      Private key for signing         (defaults to --key)
  --sign-algorithm <alg>    Signature algorithm             (default: SHA256)

Encryption options (used when --encrypt is enabled):
  --recipient-cert <path>   Recipient's cert / public key   (defaults to --cert)

  --help                    Show this help message
`);
}

// ── Load config from JSON file ──────────────────────────────────────────────
function loadConfigFile (filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    console.log(`[config] Loaded options from ${filePath}`);
    return parsed;
  } catch (err) {
    console.error(`Failed to load config file (${filePath}):`, err.message);
    process.exit(1);
  }
}

function parseArgs (argv) {
  const args = argv.slice(2);

  // ── First pass: look for --config to load defaults from file ──────────────
  let fileConfig = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--config" && args[i + 1]) {
      fileConfig = loadConfigFile(args[i + 1]);
      break;
    }
  }

  const config = {
    host: fileConfig.host || "localhost",
    port: fileConfig.port || 5671,
    vhost: fileConfig.vhost || "/",
    queue: fileConfig.queue || "example-queue",
    ca: fileConfig.ca || path.join(__dirname, "certs", "ca.pem"),
    cert: fileConfig.cert || path.join(__dirname, "certs", "client-cert.pem"),
    key: fileConfig.key || path.join(__dirname, "certs", "client-key.pem"),
    payload: fileConfig.payload || "Hello from mTLS AMQP client!",
    payloadFile: fileConfig.payloadFile || null,
    count: fileConfig.count || 1,
    // Feature switches
    sign: fileConfig.sign || false,
    encrypt: fileConfig.encrypt || false,
    // Signing
    signingKey: fileConfig.signingKey || null,
    signAlgorithm: fileConfig.signAlgorithm || "SHA256",
    // Encryption
    recipientCert: fileConfig.recipientCert || null,
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
      case "--payload":
        config.payload = args[++i];
        break;
      case "--payload-file":
        config.payloadFile = args[++i];
        break;
      case "--count":
        config.count = parseInt(args[++i], 10);
        break;
      case "--config":
        // Already handled in first pass, skip the value
        i++;
        break;
      case "--sign":
        config.sign = true;
        break;
      case "--encrypt":
        config.encrypt = true;
        break;
      case "--signing-key":
        config.signingKey = args[++i];
        break;
      case "--sign-algorithm":
        config.signAlgorithm = args[++i];
        break;
      case "--recipient-cert":
        config.recipientCert = args[++i];
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

  if (!config.signingKey) config.signingKey = config.key;
  if (!config.recipientCert) config.recipientCert = config.cert;

  // Load payload from file if --payload-file is specified
  if (config.payloadFile) {
    try {
      config.payload = fs.readFileSync(config.payloadFile, "utf8");
    } catch (err) {
      console.error("Failed to load payload file:", err.message);
      process.exit(1);
    }
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

// ── Digital signature ───────────────────────────────────────────────────────
function signPayload (payload, privateKeyPem, algorithm) {
  const sign = crypto.createSign(algorithm);
  sign.update(payload);
  sign.end();
  return sign.sign(privateKeyPem, "base64");
}

// ── Hybrid encryption (AES-256-GCM + RSA-OAEP) ─────────────────────────────
function encryptPayload (plaintext, recipientPem) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  let ciphertext = cipher.update(plaintext, "utf8", "base64");
  ciphertext += cipher.final("base64");
  const authTag = cipher.getAuthTag().toString("base64");

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

// ── Build the AMQP message ──────────────────────────────────────────────────
function buildMessage (verbose) {
  const plaintext = config.payload;
  let body = plaintext;
  const appProps = {};

  if (verbose) {
    const features = [];
    if (!config.sign && !config.encrypt) features.push("plain");
    if (config.sign) features.push("signed");
    if (config.encrypt) features.push("encrypted");
    console.log(`[mode] ${features.join(" + ")}`);
  }

  // ── Step 1: Sign the original plaintext ───────────────────────────────────
  if (config.sign) {
    const signingKeyPem = fs.readFileSync(config.signingKey);
    const signature = signPayload(plaintext, signingKeyPem, config.signAlgorithm);
    appProps["x-signature"] = signature;
    appProps["x-signature-algorithm"] = config.signAlgorithm;
    if (verbose) {
      console.log("[sign] algorithm:", config.signAlgorithm);
      console.log("[sign] signature:", signature);
    }
  }

  // ── Step 2: Encrypt the payload (body becomes ciphertext) ─────────────────
  if (config.encrypt) {
    const recipientPem = fs.readFileSync(config.recipientCert);
    const encrypted = encryptPayload(plaintext, recipientPem);
    body = encrypted.ciphertext;
    appProps["x-encrypted"] = "true";
    appProps["x-encryption-algorithm"] = "aes-256-gcm+rsa-oaep-sha256";
    appProps["x-encrypted-key"] = encrypted.encryptedKey;
    appProps["x-encryption-iv"] = encrypted.iv;
    appProps["x-encryption-tag"] = encrypted.authTag;
    if (verbose) {
      console.log("[encrypt] ciphertext:", encrypted.ciphertext);
      console.log("[encrypt] encrypted AES key:", encrypted.encryptedKey);
      console.log("[encrypt] iv:", encrypted.iv);
      console.log("[encrypt] authTag:", encrypted.authTag);
    }
  }

  return { body, application_properties: appProps };
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();
  const container = rhea.create_container();
  const total = config.count;
  let sent = 0;
  let accepted = 0;
  let rejected = 0;
  let startTime;
  const sendTimestamps = [];  // hrtime per message for latency tracking
  const latencies = [];       // ms per message (send → disposition)

  container.on("connection_open", (context) => {
    console.log("[connected] AMQP connection established via mTLS");
    if (total > 1) console.log(`[throughput] Sending ${total} messages …`);
    context.connection.open_sender(config.queue);
  });

  container.on("connection_close", () => {
    console.log("[disconnected] AMQP connection closed");
  });

  container.on("connection_error", (context) => {
    const err = context.connection.error || context.error;
    console.error("[connection_error]", err ? err.message || err : "unknown");
  });

  container.on("sendable", (context) => {
    if (!startTime) startTime = process.hrtime.bigint();
    const verbose = total === 1;

    while (sent < total && context.sender.sendable()) {
      if (verbose) console.log("[payload] plaintext:", JSON.stringify(config.payload));
      const message = buildMessage(verbose);
      sendTimestamps.push(process.hrtime.bigint());
      context.sender.send(message);
      sent++;
      if (verbose) {
        console.log("[sent] message delivered to queue");
      } else if (sent % 1000 === 0 || sent === total) {
        process.stdout.write(`\r[sending] ${sent}/${total}`);
      }
    }

    if (sent >= total && !verbose) {
      process.stdout.write("\n");
    }
  });

  function closeWhenDone (context) {
    if (accepted + rejected >= total) {
      printStats(startTime, total, accepted, rejected, latencies);
      context.sender.close();
      context.connection.close();
    }
  }

  container.on("accepted", (context) => {
    const now = process.hrtime.bigint();
    const idx = accepted + rejected;
    if (idx < sendTimestamps.length) {
      latencies.push(Number(now - sendTimestamps[idx]) / 1e6);
    }
    accepted++;
    if (total === 1) {
      console.log("[accepted] Message was accepted by the broker");
    }
    closeWhenDone(context);
  });

  container.on("rejected", (context) => {
    const now = process.hrtime.bigint();
    const idx = accepted + rejected;
    if (idx < sendTimestamps.length) {
      latencies.push(Number(now - sendTimestamps[idx]) / 1e6);
    }
    rejected++;
    if (total === 1) {
      console.error("[rejected] Message was rejected by the broker");
    }
    closeWhenDone(context);
  });

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

function percentile (sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

function printStats (startTime, total, accepted, rejected, latencies) {
  const elapsed = Number(process.hrtime.bigint() - startTime) / 1e6; // ms
  const elapsedSec = elapsed / 1000;
  const rate = total / elapsedSec;

  console.log();
  console.log("── throughput stats ────────────────────────────────────");
  console.log(`  total sent:     ${total}`);
  console.log(`  accepted:       ${accepted}`);
  console.log(`  rejected:       ${rejected}`);
  console.log(`  elapsed:        ${elapsed.toFixed(2)} ms (${elapsedSec.toFixed(3)} s)`);
  console.log(`  throughput:     ${rate.toFixed(2)} msg/s`);
  console.log(`  avg latency:    ${(elapsed / total).toFixed(3)} ms/msg`);

  if (latencies.length > 0) {
    const sorted = latencies.slice().sort((a, b) => a - b);
    console.log();
    console.log("  latency percentiles (send → disposition):");
    console.log(`    min:          ${sorted[0].toFixed(3)} ms`);
    console.log(`    p50:          ${percentile(sorted, 50).toFixed(3)} ms`);
    console.log(`    p75:          ${percentile(sorted, 75).toFixed(3)} ms`);
    console.log(`    p90:          ${percentile(sorted, 90).toFixed(3)} ms`);
    console.log(`    p95:          ${percentile(sorted, 95).toFixed(3)} ms`);
    console.log(`    p99:          ${percentile(sorted, 99).toFixed(3)} ms`);
    console.log(`    max:          ${sorted[sorted.length - 1].toFixed(3)} ms`);
  }

  console.log("───────────────────────────────────────────────────────");
}

main();
