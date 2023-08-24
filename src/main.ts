import { computeMIC, computePMK, computePTK } from "./lib";

/** ==== DICTIONARY SETUP =================================================== */
// TODO: import from file
const dictionary = [ "password", "test123", "ooooops", "ciaociao", "caiocaio" ];


/** ==== INPUT DATA ========================================================= */
const eapolPacket1 = "your_packet_here";
const eapolPacket2 = "your_packet_here";
const ssid = "your_network_name_here";


/** ==== MAIN =============================================================== */
// Retrieve source AP's MAC address and AP's nonce from first packet
console.log("\n---- PARSING EAPOL PACKET #1 ----");
const { mac: macAp, nonce: nonceAp } = parseEapolPacket(eapolPacket1);

// Retrieve source STA's MAC address and STA's nonce from second packet
console.log("\n---- PARSING EAPOL PACKET #2 ----");
const { mac: macSta, nonce: nonceSta, eapolData, mic } = parseEapolPacket(eapolPacket2);
console.log();

// Check every passphrase in the dictionary and print the outcome
let foundPassphrase: string | undefined = undefined;
for(const passphrase of dictionary) {
  foundPassphrase = compute(passphrase, ssid, macAp, macSta, nonceAp, nonceSta, eapolData, mic);

  if(foundPassphrase) break;
}
if(foundPassphrase) console.log(`PASSPHRASE FOUND! [${foundPassphrase}]`);
else                console.log(`PASSPHRASE NOT FOUND!`);


/** ==== PACKET PARSING ===================================================== */
function parseEapolPacket(eapolPacket: string) {

  // Retrieve frame header length and remove it (substring from next byte)
  const radiotapHeaderSize: number = parseInt(eapolPacket.substring(4, 6), 16);
  eapolPacket = eapolPacket.substring(radiotapHeaderSize*2);

  // Read source address from QoS header (26 byte, fixed size) and remove it
  const qosHeader: string = eapolPacket.substring(0, 52);
  const mac: string = qosHeader.substring(20, 32);
  eapolPacket = eapolPacket.substring(52);

  // Remove Logical Link Control (8 byte, fixed size)
  eapolPacket = eapolPacket.substring(16);

  // Retrieve eapol body length and read it with headers (4 byte, fixed size)
  // OR: trim off last 4 bytes, used as Frame Check Sequence at the frame layer
  const eapolBodySize: number = parseInt(eapolPacket.substring(4, 8), 16);
  let eapolData: string = eapolPacket.substring(0, (eapolBodySize+4)*2);

  // Read nonce from the eapol data
  const nonce: string = eapolData.substring(17*2, (17+32)*2);

  // Read MIC from eapol data, remove it from the to-be-processed 
  const mic: string = eapolData.substring(81*2, (81+16)*2);
  eapolData = replaceAt(eapolData, 81*2, (81+16)*2, "0".repeat(32))

  console.log("SOURCE: " + mac);
  console.log("NONCE: " + nonce);
  console.log("EAPOL DATA: " + eapolPacket);
  console.log("MIC: " + mic);

  return { mac, nonce, mic, eapolData };
}

/** ==== HASHING ============================================================ */
function compute(
  passphrase: string, ssid: string,
  macAp: string, macSta: string,
  nonceAp: string, nonceSta: string,
  data: string, expectedMic: string
): string | undefined {
  const pmk: Buffer = computePMK(passphrase, ssid);
  const ptk: Buffer = computePTK(pmk, macAp, macSta, nonceAp, nonceSta);
  const mic: Buffer = computeMIC(ptk, data);

  const micStr: string = mic.toString("hex");
  console.log(`MIC for passphrase ${passphrase}:\t${micStr}`);

  if(micStr == expectedMic) return passphrase;
  return undefined;
}

/** ==== UTILS ============================================================== */
function replaceAt(s: string, start: number, end: number, r: string): string {
  return s.slice(0, start) + r + s.slice(end);
}