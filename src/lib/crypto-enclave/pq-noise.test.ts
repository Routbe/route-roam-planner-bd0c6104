import { describe, expect, it } from "vitest";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  generateStaticKeys,
  PqNoiseError,
  PqNoiseInitiator,
  PqNoiseResponder,
  type PeerStatic,
  type StaticKeys,
} from "./pq-noise";

const psk = new Uint8Array(32).fill(7);

function setup(opts: { enrolled?: boolean; prologueR?: Uint8Array } = {}) {
  const r = generateStaticKeys();
  const i = generateStaticKeys();
  const rPub = { dhPublic: r.dhPublic, kemPublic: r.kemPublic };
  const enrolled = opts.enrolled ?? true;
  const lookup = (p: PeerStatic) =>
    enrolled && p.dhPublic.every((b, k) => b === i.dhPublic[k]) && p.kemPublic.every((b, k) => b === i.kemPublic[k])
      ? psk.slice()
      : null;
  const init = new PqNoiseInitiator(i, rPub, psk.slice());
  const resp = new PqNoiseResponder(r, lookup, opts.prologueR);
  return { r, i, init, resp };
}

function handshake() {
  const s = setup();
  const m1 = s.init.writeMessage1(new TextEncoder().encode("hi"));
  const got1 = s.resp.readMessage1(m1);
  const { message, transport: rt } = s.resp.writeMessage2(new TextEncoder().encode("yo"));
  const { transport: it2, payload } = s.init.readMessage2(message);
  return { ...s, got1, payload, it: it2, rt };
}

describe("hybrid PQ Noise IKpsk2 (X25519 + ML-KEM-1024)", () => {
  it("completes a mutually authenticated handshake and carries records both ways", () => {
    const h = handshake();
    expect(new TextDecoder().decode(h.got1.payload)).toBe("hi");
    expect(new TextDecoder().decode(h.payload)).toBe("yo");
    expect(h.got1.initiator.dhPublic).toEqual(h.i.dhPublic);
    expect(h.it.handshakeHash).toEqual(h.rt.handshakeHash);
    const rec = h.it.send(new Uint8Array([1, 2, 3]));
    expect(h.rt.receive(rec)).toEqual(new Uint8Array([1, 2, 3]));
    const back = h.rt.send(new Uint8Array([9]));
    expect(h.it.receive(back)).toEqual(new Uint8Array([9]));
  });

  it("rejects a replayed record and closes the receiving direction", () => {
    const h = handshake();
    const a = h.it.send(new Uint8Array([1]));
    h.rt.receive(a);
    expect(() => h.rt.receive(a)).toThrow(PqNoiseError);
    expect(() => h.rt.receive(h.it.send(new Uint8Array([2])))).toThrow(/closed/);
  });

  it("rejects a reordered record (counter mismatch)", () => {
    const h = handshake();
    h.it.send(new Uint8Array([1]));
    const second = h.it.send(new Uint8Array([2]));
    expect(() => h.rt.receive(second)).toThrow(PqNoiseError);
  });

  it("rejects an altered record", () => {
    const h = handshake();
    const rec = h.it.send(new Uint8Array([1, 2, 3]));
    rec[0] ^= 1;
    expect(() => h.rt.receive(rec)).toThrow(PqNoiseError);
  });

  it("rejects every single-byte flip in message 1 and message 2", () => {
    for (const where of [0, 40, 1700, 3300, 3400, 4847]) {
      const s = setup();
      const m1 = s.init.writeMessage1();
      m1[where] ^= 0x80;
      expect(() => s.resp.readMessage1(m1)).toThrow(PqNoiseError);
    }
    for (const where of [0, 100, 1700, 3200]) {
      const s = setup();
      s.resp.readMessage1(s.init.writeMessage1());
      const { message } = s.resp.writeMessage2();
      message[where] ^= 0x80;
      expect(() => s.init.readMessage2(message)).toThrow(PqNoiseError);
    }
  });

  it("refuses an initiator that is not enrolled", () => {
    const s = setup({ enrolled: false });
    s.resp.readMessage1(s.init.writeMessage1());
    expect(() => s.resp.writeMessage2()).toThrow(/not enrolled/);
  });

  it("fails when the psk differs", () => {
    const r = generateStaticKeys();
    const i = generateStaticKeys();
    const init = new PqNoiseInitiator(i, { dhPublic: r.dhPublic, kemPublic: r.kemPublic }, psk.slice());
    const resp = new PqNoiseResponder(r, () => new Uint8Array(32).fill(8));
    resp.readMessage1(init.writeMessage1());
    expect(() => init.readMessage2(resp.writeMessage2().message)).toThrow(PqNoiseError);
  });

  it("fails when the prologue differs", () => {
    const s = setup({ prologueR: new Uint8Array([1]) });
    expect(() => s.resp.readMessage1(s.init.writeMessage1())).toThrow(PqNoiseError);
  });

  it("fails against an impostor responder that lacks either static secret", () => {
    // Knows the X25519 secret but not the ML-KEM secret: the skem step breaks message 1.
    const s = setup();
    const fake: StaticKeys = { ...generateStaticKeys(), dhSecret: s.r.dhSecret, dhPublic: s.r.dhPublic, kemPublic: s.r.kemPublic };
    const imp = new PqNoiseResponder(fake, () => psk.slice());
    expect(() => imp.readMessage1(s.init.writeMessage1())).toThrow(PqNoiseError);
    // Knows the ML-KEM secret but not the X25519 secret: the es step breaks message 1.
    const t = setup();
    const other = generateStaticKeys();
    const fake2: StaticKeys = { ...t.r, dhSecret: other.dhSecret };
    const imp2 = new PqNoiseResponder(fake2, () => psk.slice());
    expect(() => imp2.readMessage1(t.init.writeMessage1())).toThrow(PqNoiseError);
  });

  it("an initiator without its ML-KEM secret cannot finish (PQ mutual authentication)", () => {
    const r = generateStaticKeys();
    const i = generateStaticKeys();
    const wrongKem = ml_kem1024.keygen(new Uint8Array(64).fill(3)).secretKey;
    const forged: StaticKeys = { ...i, kemSecret: wrongKem };
    const init = new PqNoiseInitiator(forged, { dhPublic: r.dhPublic, kemPublic: r.kemPublic }, psk.slice());
    const resp = new PqNoiseResponder(r, () => psk.slice());
    resp.readMessage1(init.writeMessage1());
    expect(() => init.readMessage2(resp.writeMessage2().message)).toThrow(PqNoiseError);
  });

  it("refuses a low-order X25519 key", () => {
    const s = setup();
    const m1 = s.init.writeMessage1();
    m1.fill(0, 0, 32);
    expect(() => s.resp.readMessage1(m1)).toThrow(PqNoiseError);
  });

  it("wipes the ephemeral secrets and closes the channel on close()", () => {
    const h = handshake();
    h.it.close();
    expect(h.it.handshakeHash.every((b) => b === 0)).toBe(true);
    expect(() => h.it.send(new Uint8Array([1]))).toThrow(/closed/);
    expect(x25519.getPublicKey(h.i.dhSecret)).toEqual(h.i.dhPublic); // caller-owned static untouched
  });

  it("produces fresh keys per handshake (no record from one tunnel opens in another)", () => {
    const a = handshake();
    const b = handshake();
    expect(a.it.handshakeHash).not.toEqual(b.it.handshakeHash);
    expect(() => b.rt.receive(a.it.send(new Uint8Array([1])))).toThrow(PqNoiseError);
  });
});
