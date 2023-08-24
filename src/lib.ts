import { pbkdf2Sync, createHmac } from "crypto";


/** String compare utils */
const min = (s1: string, s2: string): string => s2 < s1 ? s2 : s1;
const max = (s1: string, s2: string): string => s2 > s1 ? s2 : s1;

/**
 *  PRF-512 (Pseudo-Random Function with HMAC-SHA1) implementation to produce
 *  the PTK as part of the WPA2 key derivation process.
 *  It takes the PMK, label ("Pairwise key expansion", in this case),
 *  and input data (a concatenation of MACs and nonces).
 *  Iterates through four rounds of HMAC-SHA1 computations.
 *  The computed HMAC-SHA1 digests are concatenated to produce a final result.
 *  The function returns the first 64 bytes of the concatenated result.
 */
function prf512(key: Buffer, label: string, input: Buffer): Buffer {
  let result: Buffer = Buffer.alloc(0);
  for (let i = 0; i < 4; i++) {
    const hmac = createHmac("sha1", key)
      .update(label)
      .update(Buffer.from(String.fromCharCode(0), "binary"))
      .update(input)
      .update(Buffer.from(String.fromCharCode(i), "binary"));

    const digest = hmac.digest();

    result = Buffer.concat([result, digest]);
  }

  return result.subarray(0, 64);
}


/**
 *  PSK generation uses the Password-Based Key Derivation Function 2 algorithm.
 * 
 *  Standard parameters:
 *      Wi-Fi password
 *      ESSID (Wi-Fi displayed name) as salt
 *      4096 iterations
 *      32 byte key length (256 bits /8)
 * 
 *  256 bits -> 32 byte -> 64 hex char
 *  ex: 01b8 09f9 ab2f b5dc 4798 4f52 fb2d 112e 
 *      13d8 4ccb 6b86 d4a7 193e c529 9f85 1c48
 */
export function computePMK(passphrase: string, ssid: string): Buffer {
  const iterations: number = 4096;
  const keylen: number = 32;
  return pbkdf2Sync(passphrase, ssid, iterations, keylen, "sha1");
}


/**
 *  The remaining informations needed to create the PTK are:
 *      AccessPoint (AP) MAC address (known)
 *      Client (STA) MAC address (known from 802.11 destination / source addr)
 *      ANonce, contained in the 1st packet of the handshake (AP -> STA)
 *      SNonce, contained in the 2nd packet of the handshake (STA -> AP)
 * 
 *  The MAC addresses are to be considered without the colon (:).
 *  The parameters are concatenated and used as the input of a HMAC-SHA1
 *  digest (160 bits) with "Pairwise key expansion" label.
 *  The label concurs to the key generation, is used to create different keys
 *  for different purposes even if the input values are the same.
 *  Concatenated inputs: ANonce || SNonce || MAC_AP || MAC_STA
 *  The key of the digest is the PMK previously generated.
 * 
 *  512 bits -> 64 byte -> 128 hex char
 *  ex: bf49 a95f 0494 f444 2716 2f38 696e f8b6 
 *      428b cf8b a3c6 f0d7 245a d314 a14c 0d18 
 *      efd6 38aa e653 c908 a7ab c648 0a7f 4068 
 *      2479 c970 8aaa abc3 eb7e da28 9d06 d535 
 */
export function computePTK(pmk: Buffer, macAP: string, macSTA: string, nonceAP: string, nonceSTA: string): Buffer {
  macAP = macAP.replace(/:/g, "");
  macSTA = macSTA.replace(/:/g, "");

  const input: Buffer = Buffer.concat([
    Buffer.from(min(macAP, macSTA), "hex"),
    Buffer.from(max(macAP, macSTA), "hex"),
    Buffer.from(min(nonceAP, nonceSTA), "hex"),
    Buffer.from(max(nonceAP, nonceSTA), "hex")
  ])
  
  return prf512(pmk, "Pairwise key expansion", input);
}


/**
 *  First 16 bytes of PTK are used as KCK (Key Confirmation Key) for the
 *  generation of the MIC (Message Integrity Code) sent from the client
 *  to the accesspoint during the authentication 4-way handshake (EAPOL).
 *  The MIC also has a 16 byte length.
 * 
 *  128 bits -> 16 byte -> 32 hex char
 *  ex: bf49 a95f 0494 f444 2716 2f38 696e f8b6
 * 
 *  128 bits -> 16 byte -> 32 hex char
 *  ex: 4528 2522 bc67 07d6 a70a 0317 a3ed 48f0
 */
export function computeMIC(ptk: Buffer, data: string) {
  const kck: Buffer = ptk.subarray(0, 16);
  const input: Buffer = Buffer.from(data, "hex");

  return createHmac("sha1", kck)
  .update(input)
  .digest().subarray(0, 16);
}


/* ========================================================================== *
function prettyPrintHex (hex: Buffer) {
  const bytes = hex.toString("hex").match(/.{0,4}/g);
  if(!bytes) return;

  let line = "", i = 0;
  for(const bb of bytes) {
    if(i%8 == 0) line += "\n  ";
    line += bb + " ";
    i++;
  }
  return line;
}

const PMK: Buffer = computePMK("passphrase", "ssid");
const PTK: Buffer = computePTK(PMK, "00:1e:2a:e0:bd:d0", "cc:08:e0:62:0b:c8",
  "61c9a3f5cdcdf5fae5fd760836b8008c863aa2317022c7a202434554fb38452b",
  "60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318");
const MIC: Buffer = computeMIC(PTK, "123");

console.log(`PSK is ${prettyPrintHex(PMK)}`);
console.log(`PTK is ${prettyPrintHex(PTK)}`);
console.log(`MIC is ${prettyPrintHex(MIC)}`);
/** ========================================================================= */