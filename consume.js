"use strict";

const rhea = require("rhea");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node consume.js [options]

Consumes messages from an AMQP 1.0 queue via mTLS on RabbitMQ.
Automatically detects and handles signed and/or encrypted messages based on
the application properties set by the sender (send.js).

Options:
  --config <path>           Load options from a JSON config file
  --host <hostname>         AMQP broker hostname            (default: localhost)
  --port <port>             AMQP broker port                (default: 5671)
  --vhost <vhost>           RabbitMQ virtual host            (default: /)
  --queue <address>         Queue / address name            (default: example-queue)
  --ca <path>               CA certificate file             (default: certs/ca.pem)
  --cert <path>             Client certificate file         (default: certs/client-cert.pem)
  --key <path>              Client private key file         (default: certs/client-key.pem)

Feature switches:
  --verify                  Enable signature verification
  --decrypt                 Enable decryption of encrypted payloads

Verification options (used when --verify is enabled):
  --sender-cert <path>      Sender's certificate for signature verification
                            (defaults to --cert)

Decryption options (used when --decrypt is enabled):
  --decrypt-key <path>      Private key for decryption      (defaults to --key)

Throughput:
  --count <n>               Stop after receiving n messages and print stats
                            (default: 0 = unlimited, stats on Ctrl+C)

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
    // Feature switches
    verify: fileConfig.verify || false,
    decrypt: fileConfig.decrypt || false,
    // Verification
    senderCert: fileConfig.senderCert || null,
    // Decryption
    decryptKey: fileConfig.decryptKey || null,
    // Throughput
    count: fileConfig.count || 0,
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
      case "--verify":
        config.verify = true;
        break;
      case "--decrypt":
        config.decrypt = true;
        break;
      case "--sender-cert":
        config.senderCert = args[++i];
        break;
      case "--decrypt-key":
        config.decryptKey = args[++i];
        break;
      case "--count":
        config.count = parseInt(args[++i], 10);
        break;
      case "--config":
        // Already handled in first pass, skip the value
        i++;
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

  if (!config.senderCert) config.senderCert = config.cert;
  if (!config.decryptKey) config.decryptKey = config.key;

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
function verifySignature (payload, signature, algorithm, publicKeyPem) {
  const verify = crypto.createVerify(algorithm);
  verify.update(payload);
  verify.end();
  return verify.verify(publicKeyPem, signature, "base64");
}

// ── Decryption (AES-256-GCM + RSA-OAEP) ────────────────────────────────────
function decryptPayload (ciphertext64, encryptedKey64, iv64, authTag64, privateKeyPem) {
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encryptedKey64, "base64"),
  );

  const iv = Buffer.from(iv64, "base64");
  const authTag = Buffer.from(authTag64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertext64, "base64", "utf8");
  plaintext += decipher.final("utf8");
  return plaintext;
}

// ── Process a received message ──────────────────────────────────────────────
function processMessage (msg, senderPubKey, decryptKeyPem) {
  const props = msg.application_properties || {};
  let body = typeof msg.body === "string" ? msg.body : JSON.stringify(msg.body);

  const isEncrypted = props["x-encrypted"] === "true";
  const isSigned = !!(props["x-signature"] && props["x-signature-algorithm"]);

  const flags = [];
  if (isSigned) flags.push("signed");
  if (isEncrypted) flags.push("encrypted");
  if (flags.length === 0) flags.push("plain");
  console.log("[mode]", flags.join(" + "));

  // ── Step 1: Decrypt (if encrypted) ────────────────────────────────────────
  let plaintext = body;
  if (isEncrypted) {
    if (!config.decrypt) {
      console.warn("[decrypt]  ⚠  Message is encrypted but --decrypt is not enabled — showing raw ciphertext");
      console.log("[received] ciphertext:", body);
    } else {
      const encryptedKey = props["x-encrypted-key"];
      const iv = props["x-encryption-iv"];
      const authTag = props["x-encryption-tag"];
      const algorithm = props["x-encryption-algorithm"];

      console.log("[decrypt]  algorithm:", algorithm);
      try {
        plaintext = decryptPayload(body, encryptedKey, iv, authTag, decryptKeyPem);
        console.log("[decrypt]  ✔  plaintext:", plaintext);
      } catch (err) {
        console.error("[decrypt]  ✘  Decryption failed:", err.message);
        return;
      }
    }
  } else {
    console.log("[received] payload:", body);
  }

  // ── Step 2: Verify signature (against the plaintext) ──────────────────────
  if (isSigned) {
    if (!config.verify) {
      console.warn("[verify]   ⚠  Message is signed but --verify is not enabled — skipping verification");
    } else {
      const signature = props["x-signature"];
      const algorithm = props["x-signature-algorithm"];

      console.log("[verify]   algorithm:", algorithm);
      console.log("[verify]   signature:", signature);

      try {
        // The signature is always over the original plaintext
        const valid = verifySignature(plaintext, signature, algorithm, senderPubKey);
        if (valid) {
          console.log("[verify]   ✔  Signature is VALID");
        } else {
          console.error("[verify]   ✘  Signature is INVALID");
        }
      } catch (err) {
        console.error("[verify]   ✘  Verification failed:", err.message);
      }
    }
  }
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();

  const senderPubKey = config.verify ? fs.readFileSync(config.senderCert) : null;
  const decryptKeyPem = config.decrypt ? fs.readFileSync(config.decryptKey) : null;

  const container = rhea.create_container();
  let messageCount = 0;
  let startTime = null;
  let lastMsgTime = null;
  const interArrivals = [];  // ms between consecutive messages
  const expectCount = config.count;  // 0 = unlimited
  const verbose = expectCount === 0 || expectCount === 1;

  const features = [];
  if (!config.verify && !config.decrypt) features.push("plain only");
  if (config.verify) features.push("verify");
  if (config.decrypt) features.push("decrypt");

  container.on("connection_open", (context) => {
    console.log("[connected] AMQP connection established via mTLS");
    console.log(`[features] ${features.join(" + ")}`);
    console.log(`[listening] Waiting for messages on "${config.queue}" …`);
    if (expectCount > 0) console.log(`[throughput] Will stop after ${expectCount} messages`);
    console.log();
    context.connection.open_receiver(config.queue);
  });

  container.on("connection_close", () => {
    console.log("[disconnected] AMQP connection closed");
  });

  container.on("connection_error", (context) => {
    const err = context.connection.error || context.error;
    console.error("[connection_error]", err ? err.message || err : "unknown");
  });

  container.on("message", (context) => {
    // Ignore messages beyond the expected count (in-flight overshoot)
    if (expectCount > 0 && messageCount >= expectCount) return;

    if (!startTime) startTime = process.hrtime.bigint();
    const now = process.hrtime.bigint();
    if (lastMsgTime) {
      interArrivals.push(Number(now - lastMsgTime) / 1e6);
    }
    lastMsgTime = now;
    messageCount++;

    if (verbose) {
      console.log(`── message #${messageCount} ──────────────────────────────────`);
      processMessage(context.message, senderPubKey, decryptKeyPem);
      console.log();
    } else {
      // Quiet mode for bulk — still process (decrypt/verify) but don't log each message
      processMessageQuiet(context.message, decryptKeyPem);
      if (messageCount % 1000 === 0 || messageCount === expectCount) {
        process.stdout.write(`\r[receiving] ${messageCount}/${expectCount}`);
      }
    }

    if (expectCount > 0 && messageCount >= expectCount) {
      if (!verbose) process.stdout.write("\n");
      printStats(startTime, messageCount, interArrivals);
      context.receiver.close();
      context.connection.close();
    }
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

  process.on("SIGINT", () => {
    console.log("\n[shutdown] Received SIGINT, closing connection …");
    if (startTime && messageCount > 0) {
      printStats(startTime, messageCount, interArrivals);
    }
    container.connections && container.connections.forEach((c) => c.close());
    setTimeout(() => process.exit(0), 500);
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

/**
 * Quiet message processing for bulk throughput tests.
 * Still decrypts/verifies but does not log per-message details.
 */
function processMessageQuiet (msg, decryptKeyPem) {
  const props = msg.application_properties || {};
  const isEncrypted = props["x-encrypted"] === "true";

  if (isEncrypted && config.decrypt && decryptKeyPem) {
    const encryptedKey = props["x-encrypted-key"];
    const iv = props["x-encryption-iv"];
    const authTag = props["x-encryption-tag"];
    const body = typeof msg.body === "string" ? msg.body : JSON.stringify(msg.body);
    decryptPayload(body, encryptedKey, iv, authTag, decryptKeyPem);
  }
}

function percentile (sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

function printStats (startTime, count, interArrivals) {
  const elapsed = Number(process.hrtime.bigint() - startTime) / 1e6; // ms
  const elapsedSec = elapsed / 1000;
  const rate = count / elapsedSec;

  console.log();
  console.log("── throughput stats ────────────────────────────────────");
  console.log(`  total received: ${count}`);
  console.log(`  elapsed:        ${elapsed.toFixed(2)} ms (${elapsedSec.toFixed(3)} s)`);
  console.log(`  throughput:     ${rate.toFixed(2)} msg/s`);
  console.log(`  avg latency:    ${(elapsed / count).toFixed(3)} ms/msg`);

  if (interArrivals.length > 0) {
    const sorted = interArrivals.slice().sort((a, b) => a - b);
    console.log();
    console.log("  inter-arrival percentiles:");
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
