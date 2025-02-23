# Verity

Verity is a tiny, super-fast server for [Altcha](https://altcha.org/), a Proof-of-Work based CAPTCHA.

## Features

* Uses the official [altcha-lib-go](https://github.com/altcha-org/altcha-lib-go) library, ensuring compatibility with official Altcha libraries.
* Single, lightweight binary (less than 14MB) written in Go, suitable for resource-constrained environments like a Raspberry Pi.
* Flexible configuration through command-line flags (`./verity --help`), environment variables (`VERITY_XXX`), and a YAML file (`./verity.yaml`).
* Automatic secure HMAC key generation and a basic API key generator.
* Configurable challenge algorithm (SHA256, SHA512), maximum complexity, and challenge expiration time.
* Security features:
    * Protection against challenge replay attacks.
    * Dynamic adjustment of maximum complexity based on request volume.
    * Strict enforcement of challenge expiration.
    * API key-based authentication.
    * Origin header checks.

## Installation

1.  Clone the repository: `git clone https://github.com/Flameborn/verity`
2.  Navigate to the directory: `cd verity`
3.  Build the binary: `go build`

## Usage

1.  **Generate configuration and API key:**
    * `./verity add domain1,domain2,...` (Replace `domain1,domain2,...` with your domains). This command will generate a default configuration file and add an API key that is valid for the provided domains.
2.  **Start the server:**
    * `./verity`
    * **Note:** It is strongly recommended to use a reverse proxy, such as Caddy, in front of Verity for enhanced security and performance.

## API Endpoints

* **Request Challenge:**
    * `GET /api/v1/challenge?apiKey=vrty_XXX`
    * Returns a JSON object that the official JavaScript client can process.
* **Verify Challenge:**
    * `POST /api/v1/challenge/verify?apiKey=vrty_XXX`
    * The request body should contain the base64-encoded JSON representing the solved challenge (typically from the `altcha` form field).
    * Returns a JSON object with `code` and `message` fields (e.g., `{"code": 200, "message": "OK"}`).
* **Credits and Stats:**
    * `GET /`
    * Returns a basic HTML page with credits and server statistics.

## Configuration

Verity can be configured through command-line flags, environment variables, or a YAML file. For details, run `./verity --help`, and see the configuration file.

## License

MIT License

## Contributions

Contributions are welcome! Testing on various devices is particularly valuable. Please feel free to submit pull requests or report issues. Every effort has been made to make Verity production-ready as much as possible for a two-day project.
