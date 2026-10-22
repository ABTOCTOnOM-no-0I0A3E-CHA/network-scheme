import { writeFileSync } from "node:fs";

/*
 * Writes the notification sound: a 0.3 s 880 Hz sine beep with a short fade in/out,
 * 16-bit mono PCM at 22.05 kHz. Generated here, so the file is ours (no third-party licence).
 * Run: bun scripts/gen-alert.ts src/assets/alert.wav
 */
const RATE = 22050;
const SECONDS = 0.3;
const FREQ = 880;
const FADE = 0.03;

const n = Math.round(RATE * SECONDS);
const buf = Buffer.alloc(44 + n * 2);
buf.write("RIFF", 0);
buf.writeUInt32LE(36 + n * 2, 4);
buf.write("WAVEfmt ", 8);
buf.writeUInt32LE(16, 16);
buf.writeUInt16LE(1, 20);
buf.writeUInt16LE(1, 22);
buf.writeUInt32LE(RATE, 24);
buf.writeUInt32LE(RATE * 2, 28);
buf.writeUInt16LE(2, 32);
buf.writeUInt16LE(16, 34);
buf.write("data", 36);
buf.writeUInt32LE(n * 2, 40);
for (let i = 0; i < n; i++) {
  const t = i / RATE;
  const env = Math.min(1, t / FADE, (SECONDS - t) / FADE);
  buf.writeInt16LE(Math.round(Math.sin(2 * Math.PI * FREQ * t) * env * 0.4 * 32767), 44 + i * 2);
}
writeFileSync(process.argv[2] ?? "alert.wav", buf);
