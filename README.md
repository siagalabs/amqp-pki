# sipg-task-6

AMQP 1.0 client scripts for RabbitMQ using **mTLS** authentication (EXTERNAL SASL) with the [rhea](https://github.com/amqp/rhea) library.

Supports optional **digital signature** and **hybrid encryption** (AES-256-GCM + RSA-OAEP) of message payloads.

## Prerequisites

- Node.js ≥ 16
- RabbitMQ with AMQP 1.0 plugin and TLS/EXTERNAL SASL enabled
- Client certificates (CA, cert, key) for mTLS

## Install

```bash
npm install
```

## Certificate Setup

Place your certificate files in the `certs/` directory (git-ignored):

```
certs/
├── ca.pem              # CA certificate
├── client-cert.pem     # Client certificate
└── client-key.pem      # Client private key
```

## Scripts

### `send.js` — Unified Sender (recommended)

Sends a message with optional signing and/or encryption via CLI switches.

```bash
# Plain message
node send.js --host <broker> --ca <ca> --cert <cert> --key <key> \
  --payload "Hello world"

# Load payload from file
node send.js --host <broker> --ca <ca> --cert <cert> --key <key> \
  --payload-file ./sample-payload/fixm/fixm1.xml

# Signed only
node send.js --sign --host <broker> --ca <ca> --cert <cert> --key <key>

# Encrypted only
node send.js --encrypt --host <broker> --ca <ca> --cert <cert> --key <key>

# Signed + Encrypted
node send.js --sign --encrypt --host <broker> --ca <ca> --cert <cert> --key <key>

# Using a config file
node send.js --config config.send.sample.json

# Config file + CLI overrides
node send.js --config config.send.sample.json --payload-file ./sample-payload/fixm/fixm1.xml

# Send 1000 messages and print throughput stats
node send.js --config config.send.sample.json --count 1000
```

**Options:**

| Option | Description | Default |
|---|---|---|
| `--config <path>` | Load options from a JSON config file | — |
| `--host <hostname>` | AMQP broker hostname | `localhost` |
| `--port <port>` | AMQP broker port | `5671` |
| `--vhost <vhost>` | RabbitMQ virtual host | `/` |
| `--queue <address>` | Queue / address name | `example-queue` |
| `--ca <path>` | CA certificate file | `certs/ca.pem` |
| `--cert <path>` | Client certificate file | `certs/client-cert.pem` |
| `--key <path>` | Client private key file | `certs/client-key.pem` |
| `--payload <text>` | Message payload text | `Hello from mTLS AMQP client!` |
| `--payload-file <path>` | Load payload from file (overrides `--payload`) | — |
| `--sign` | Enable digital signature | disabled |
| `--encrypt` | Enable hybrid encryption | disabled |
| `--signing-key <path>` | Private key for signing | defaults to `--key` |
| `--sign-algorithm <alg>` | Signature algorithm | `SHA256` |
| `--recipient-cert <path>` | Recipient's cert for encryption | defaults to `--cert` |
| `--count <n>` | Number of messages to send (prints throughput stats) | `1` |

---

### `consume.js` — Unified Consumer (recommended)

Consumes messages with optional signature verification and/or decryption.

```bash
# Plain consumer
node consume.js --host <broker> --ca <ca> --cert <cert> --key <key>

# Verify + Decrypt
node consume.js --verify --decrypt --host <broker> --ca <ca> --cert <cert> --key <key>

# Using a config file
node consume.js --config config.consume.sample.json

# Consume exactly 1000 messages and print stats
node consume.js --config config.consume.sample.json --count 1000
```

**Options:**

| Option | Description | Default |
|---|---|---|
| `--config <path>` | Load options from a JSON config file | — |
| `--verify` | Enable signature verification | disabled |
| `--decrypt` | Enable decryption | disabled |
| `--sender-cert <path>` | Sender's cert for verification | defaults to `--cert` |
| `--decrypt-key <path>` | Private key for decryption | defaults to `--key` |
| `--count <n>` | Stop after receiving n messages and print stats | — (runs forever) |

Press `Ctrl+C` to stop the consumer (also prints stats if `--count` was used).

---

### Single-purpose scripts

| Script | Description |
|---|---|
| `index.js` | Basic AMQP 1.0 mTLS connection (send + receive) |
| `send-signed.js` | Send a digitally signed message |
| `consume-verify.js` | Consume and verify signed messages |
| `send-encrypted.js` | Send a hybrid-encrypted message |
| `consume-decrypt.js` | Consume and decrypt encrypted messages |

All scripts share the same connection and TLS options as `send.js`/`consume.js`.

## Config File

Both `send.js` and `consume.js` support `--config <path>` to load options from a JSON file. CLI arguments override config file values.

Sample sender config (`config/config.send.sample.json`):

```json
{
  "host": "localhost",
  "port": 5671,
  "vhost": "/",
  "queue": "example-queue",
  "ca": "certs/amqp-client.chain.pem",
  "cert": "certs/amqp-client.cert.pem",
  "key": "certs/amqp-client.key.pem",
  "sign": true,
  "encrypt": true
}
```

Sample consumer config (`config/config.consume.sample.json`):

```json
{
  "host": "localhost",
  "port": 5671,
  "ca": "certs/amqp-client.chain.pem",
  "cert": "certs/amqp-client.cert.pem",
  "key": "certs/amqp-client.key.pem",
  "verify": true,
  "decrypt": true
}
```


## Throughput & Percentile Stats

When `--count <n>` is specified (with n > 1), both scripts suppress per-message output and print a summary once all messages have been processed:

**Sender** (`send.js`) reports:
- Total sent / accepted / rejected
- Elapsed time and throughput (msg/s)
- Latency percentiles (send → broker disposition): min, p50, p75, p90, p95, p99, max

**Consumer** (`consume.js`) reports:
- Total received
- Elapsed time and throughput (msg/s)
- Inter-arrival time percentiles: min, p50, p75, p90, p95, p99, max

Example output:

```
── throughput stats ────────────────────────────────────
  total sent:     1000
  accepted:       1000
  rejected:       0
  elapsed:        823.45 ms (0.823 s)
  throughput:     1214.40 msg/s
  avg latency:    0.823 ms/msg

  latency percentiles (send → disposition):
    min:          0.112 ms
    p50:          0.543 ms
    p75:          0.891 ms
    p90:          1.234 ms
    p95:          1.567 ms
    p99:          2.345 ms
    max:          5.678 ms
───────────────────────────────────────────────────────
```

## How It Works

### mTLS Authentication

All scripts connect over TLS and use the **EXTERNAL** SASL mechanism. RabbitMQ authenticates the client based on the CN in the client certificate — no username/password required.

### Digital Signature

When `--sign` is enabled, the sender:
1. Computes a signature over the **plaintext** using `crypto.createSign(algorithm)`
2. Attaches the base64-encoded signature and algorithm name as AMQP application properties (`x-signature`, `x-signature-algorithm`)

The consumer verifies using `crypto.createVerify()` with the sender's certificate.

### Hybrid Encryption

When `--encrypt` is enabled, the sender:
1. Generates a random 256-bit AES key and 96-bit IV
2. Encrypts the payload with **AES-256-GCM** → ciphertext + auth tag
3. Wraps the AES key with the recipient's RSA public key using **RSA-OAEP (SHA-256)**
4. Sends the ciphertext as the message body with encryption metadata in application properties

The consumer unwraps the AES key with its private key and decrypts the ciphertext.

### Sign + Encrypt

When both are enabled, the signature is computed over the **original plaintext** before encryption. On the consumer side, decryption happens first, then the signature is verified against the recovered plaintext.

## License

TEH TARIK-WARE