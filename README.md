![Alt text](https://github.com/D3N14LD15K/cartograph3r/blob/main/.img/cartograph3r_banner.png?raw=true)


# Cartograph3r — Map the Frontier of Client-Side Code

> _"After chasing ghosts through minified JS and dead-end .map files with tools that don’t really see the whole picture, I built my own damn trail."_

`cartograph3r` is a **precision reconnaissance engine** built for bug bounty hunters who want to **go deeper than surface-level crawling**.

It doesn’t just find `.js` files... it **maps them**.  
It **downloads their souls** (SourceMaps) and it brings back **structured intel** you can chain into `trufflehog`, `ripgrep`, or your own exploit pipeline.

---

## 🎯 Why I created this tool?

Modern web apps hide critical logic in:
- Minified JavaScript
- SourceMap (`.map`) files
- Dynamic imports
- Inline scripts

Most tools stop at listing URLs.  
`cartograph3r` goes further:
- Discovers `.js` files via deep crawl
- Validates they’re alive
- Downloads them
- Extracts `sourceMappingURL` from:
  - Comments (`//# sourceMappingURL=`)
  - HTTP headers (`SourceMap`, `X-SourceMap`)
  - Heuristics (`foo.js.map`)
  - Data URIs (embedded maps)
- Resolves and downloads `.map` files
- Keeps a clean, structured output for automation

Because the real attack surface isn’t in the API docs.  
It’s in the **minified mess no one reads** — until now.

---

## 🔧 Features

- ✅ Deep crawl with `katana` (`-jc`, `-jsl`, depth 4)
- ✅ Live JS validation with `httpx`
- ✅ Smart `.map` extraction (all known methods)
- ✅ Handles encoded paths, spaces, `[`, `]`
- ✅ Data-URI support for embedded SourceMaps
- ✅ Structured TSV output for chaining tools
- ✅ Safe defaults: no form submission, low concurrency
- ✅ Built for **real-world bug hunting**

---

## 🛠️ Requirements and install

- [`katana`](https://github.com/projectdiscovery/katana)
- [`httpx`](https://github.com/projectdiscovery/httpx)
- `curl`
- `jq`
- `python3` (for URL parsing and data-URI decoding)

Install ProjectDiscovery tools:

```bash
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Usage
Set execution permissions: 
```bash
chmod +x cartograph3r.sh
```

```bash
./cartograph3r.sh <hosts.txt> <output_dir>
```

Example
```bash
./cartograph3r.sh targets.txt jsmap-out/
```

Flags
```
-t, --target (Required)
Input file containing either base domains or live JS URLs (if used with -u)

-o, --output (Optional)
Output directory (default: jsmap-out)

-u, --urls-ready (Optional)
Skip crawling — assume input file contains direct .js URLs to download

-r, --rate-limit (Optional)
Limit requests per second (e.g., -r 5 -> 5 req/sec)

-H, --header (Optional)
Add custom headers to HTTP requests (can be used multiple times) 
-H 'X-Bugcrowd-Username: D3N14LD15K'

-h, --help
Show help menu and usage examples
```

File structure
```
jsmap-out/
├── tmp/               # Temporary files
├── urls/              # Discovered JS URLs
│   ├── js_urls_alive.txt
│   └── js_urls_raw.txt
├── js/                # Downloaded .js files (organized by host)
├── maps/              # Downloaded .map files
├── sources/           # Extracted source files
└── logs/              # Errors, download failures
```

⚠️ Warning
This tool downloads and analyzes client-side code from real applications.
Use only on AUTHORIZED targets.


📄 License
MIT — do what you want, but don’t be a d^ck.


🤝 Shoutouts: Built on the shoulders of giants

@projectdiscovery — for katana, httpx, and the whole damn ecosystem

The bug bounty community — for making tooling cool again

----
You’re not just crawling — you’re reverse-engineering the frontend.
That power comes with responsibility. 

🤠 Ready? Who wants to map the frontier?


