"use strict";

const rhea = require("rhea");
const fs = require("fs");
const path = require("path");

// ── CLI argument parsing ────────────────────────────────────────────────────
function printUsage () {
  console.log(`
Usage: node index.js [options]

Options:
  --host <hostname>   AMQP broker hostname            (default: localhost)
  --port <port>       AMQP broker port                (default: 5671)
  --vhost <vhost>     RabbitMQ virtual host            (default: /)
  --queue <address>   Queue / address name            (default: example-queue)
  --ca <path>         CA certificate file             (default: certs/ca.pem)
  --cert <path>       Client certificate file         (default: certs/client-cert.pem)
  --key <path>        Client private key file         (default: certs/client-key.pem)
  --help              Show this help message
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
      enable_sasl_external: true, // Enable EXTERNAL SASL mechanism for mTLS authentication
      rejectUnauthorized: true,
    };
  } catch (err) {
    console.error("Failed to load TLS certificates:", err.message);
    process.exit(1);
  }
}

// ── Main ────────────────────────────────────────────────────────────────────
function main () {
  const tlsOptions = loadCertificates();
  const container = rhea.create_container();

  // ── Connection events ─────────────────────────────────────────────────────
  container.on("connection_open", (context) => {
    console.log("[connected] AMQP connection established via mTLS");
    // Open a sender and a receiver on the configured queue
    context.connection.open_sender(config.queue);
    context.connection.open_receiver(config.queue);
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
    const message = { body: "Hello from mTLS AMQP client!" };
    context.sender.send(message);
    console.log("[sent]", JSON.stringify(message.body));
    // Close sender after sending one message (remove for continuous sending)
    context.sender.close();
  });

  container.on("accepted", () => {
    console.log("[accepted] Message was accepted by the broker");
  });

  container.on("rejected", (_context) => {
    console.error("[rejected] Message was rejected by the broker");
  });

  // ── Receiver events ──────────────────────────────────────────────────────
  container.on("message", (context) => {
    console.log("[received]", JSON.stringify(context.message.body));
    // Close receiver and connection after receiving one message
    context.receiver.close();
    context.connection.close();
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

  // ── Establish the mTLS connection to RabbitMQ ─────────────────────────────
  console.log(`Connecting to amqps://${config.host}:${config.port}/${encodeURIComponent(config.vhost)} using mTLS (EXTERNAL) …`);

  container.connect({
    host: config.host,
    port: config.port,
    transport: "tls",
    // RabbitMQ uses the AMQP "hostname" field in the Open frame for vhost routing
    hostname: config.vhost,
    // TLS SNI – must match the broker's certificate CN / SAN
    servername: config.host,
    // TLS / mTLS options passed directly to Node's tls.connect()
    ...tlsOptions,
    // EXTERNAL SASL – RabbitMQ authenticates via the client certificate CN
    // sasl_mechanisms: ["EXTERNAL"],
  });
}

main();
