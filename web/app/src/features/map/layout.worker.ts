/*
 * ELK's own worker script: it installs the message dispatcher on `self`. Bundled as a separate file under /assets/
 * (the panel CSP allows scripts only from there; no blob: or eval).
 */
import "elkjs/lib/elk-worker.min.js";
