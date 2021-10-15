/*
 * Copyright 2021 Nimrod Zimerman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const ZXing = require('@zxing/library');


/*** SHA256 ***/

// Perform SHA256 over a byte array.
// Returns a byte array.
async function sha256DigestPromise(byteArr) {
  const hash = await crypto.subtle.digest("sha-256", byteArr);  // Returns promise of ArrayBuffer.
  return new Uint8Array(hash);
}


/*** Conversion ***/

// Convert a binary string to an ArrayBuffer.
function binaryStrToArrayBuf(str) {
  const arrBuf = new ArrayBuffer(str.length);
  const arrBufUint8 = new Uint8Array(arrBuf);
  for (let t = 0; t < str.length; t++) {
    arrBufUint8[t] = str.charCodeAt(t);
  }
  return arrBuf;
}

// Convert a UInt8Array to a hex string.
function uint8ArrToHex(uint8Arr) {
  let hex = "";
  for (const b of uint8Arr) {
    hex += b.toString(16).padStart(2, "0");
  }

  // Also possible (but less readable) -
  // let hex = "";
  // uint8Arr.forEach(b => hex += b.toString(16).padStart(2, "0"));

  return hex;
}

// Convert an ArrayBuffer to a hex string.
function arrBufToHex(arrBuf) {
  return uint8ArrToHex (new Uint8Array(arrBuf));
}

// Convert a hex string to a UInt8Array array.
function hexToUint8Arr(hex) {
  let bytes = [];
  for (let t = 0; t < hex.length; t += 2) {
    const byte = parseInt(hex.substr(t, 2), 16)
    bytes.push (byte)
  }
  return new Uint8Array(bytes);
}


/*** Crypto ***/

function getDerPublicKeyFromPem(pemText) {

  // Based on https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#examples.

  // Fetch Base64 encoded text between PEM markers.
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemHeaderIndex = pemText.indexOf(pemHeader);
  const pemFooterIndex = pemText.indexOf(pemFooter);
  const pemBase64Text = pemText.substring(pemHeaderIndex + pemHeader.length, pemFooterIndex);

  // Decode Base64 PEM text to DER.
  const derBinaryStr = window.atob(pemBase64Text);

  // Convert from a binary string to an ArrayBuffer.
  const derPublicKey = binaryStrToArrayBuf(derBinaryStr);

  return derPublicKey;
}

// Import an RSA public key (PEM format).
// Key is imported with the specified hashing algorithm and as RSASSA-PKCS1-v1_5,
// for signature verification only.
function importRsaPublicKeyPem(pemText, hashAlgorithm) {

  const derPublicKey = getDerPublicKeyFromPem(pemText);

  return window.crypto.subtle.importKey(
    "spki",  // SubjectPublicKeyInfo format
    derPublicKey,
    {  // RsaHashedImportParams algorithm
      name: "RSASSA-PKCS1-v1_5",
      hash: hashAlgorithm,
    },
    true,  // Extractable key
    ["verify"],
  );
}

// Import an ECDSA P-256 public key (PEM format).
// Key is imported for signature verification only.
function importEcdsaPublicKeyPem(pemText) {

  const derPublicKey = getDerPublicKeyFromPem(pemText);

  return window.crypto.subtle.importKey(
    "spki",  // SubjectPublicKeyInfo format
    derPublicKey,
    { // EcKeyImportParams algorithm
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,  // Extractable key
    ["verify"],
  );
}

// Trim leading zeros ("00") in an hex string.
function trimHexLeadingZeros(hexStr) {
  while (hexStr.substr(0,2) == "00") {
    hexStr = hexStr.substr(2);
  }
  return hexStr;
};

// Convert NIST P-256 signature in ASN.1 DER format to P1363 format.
// Assumes the signature is of valid format.
// DER format is used by OpenSSL.
// P1363 format is used by WebCrypto.
function signatureDerToP1363(derSignature) {

  const derSignatureHex = arrBufToHex(derSignature);

  /* 
   * ASN.1 DER format for signature -
   *   Ecdsa-Sig-Value  ::=  SEQUENCE  {
   *     r     INTEGER,
   *     s     INTEGER  }
   * (from https://datatracker.ietf.org/doc/html/rfc3278#section-8.2,
   *  https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3)
   * 
   * This is represented in hexa-decimal string as -
   * 
   *   Offset          Value   Bytes   Description
   *   ------          -----   -----   -------------------------------
   *   0               0x30    2       SEQUENCE header
   *   2               Size    2       Size of the SEQUENCE
   *   4               0x02    2       INTEGER type
   *   6               Size    2       Size of the INTEGER "r" = size_r
   *   8               Bytes   size_r  Bytes of the INTEGER "r" (big endian)
   *   8+(size_r*2)    0x02    2       INTEGER type
   *   8+(size_r*2)+2  Size    2       Size of the INTEGER "s" = size_s
   *   8+(size_r*2)+4  Bytes   size_s  Bytes of the INTEGER "s" (big endian)
   */

  if (parseInt(derSignatureHex.substr(0, 2), 16) != 0x30) {
    throw "Expected SEQUENCE at start of signature";
  }

  if (parseInt(derSignatureHex.substr(4, 2), 16) != 0x02) {
    throw "Expected INTEGER as first value of sequence";
  }

  // Parse size of "r".
  const rSizeInHexChars = parseInt(derSignatureHex.substr(6, 2), 16) * 2;
  // Get "r".
  let r = derSignatureHex.substr(8, rSizeInHexChars);

  if (parseInt(derSignatureHex.substr(8 + rSizeInHexChars, 2), 16) != 0x02) {
    throw "Expected INTEGER as second value of sequence";
  }

  // Parse size of "s".
  const sSizeInHexChars = parseInt(derSignatureHex.substr(8 + rSizeInHexChars + 2, 2), 16) * 2;
  // Get "s".
  let s = derSignatureHex.substr(8 + rSizeInHexChars + 4, sSizeInHexChars);

  // Integers might be larger than 32 bytes in ASN.1 (because negative integers need to have a prefix of 0).
  // Integers must be exactly 32 bytes in P1363 (padded by zeros).

  // Trim all leading zeros from r and s, and pad to 32 bytes.
  r = trimHexLeadingZeros(r).padStart(32*2, "0");
  s = trimHexLeadingZeros(s).padStart(32*2, "0");

  // Make sure the resulting strings are exactly 32 bytes long.
  if ((r.length != 32*2) || (s.length != 32*2)) {
    throw "r or s are not of the expected size";
  }

  // Concatenate r and s together - that's P1363 format.
  return hexToUint8Arr(r + s);
}


/*** Main ***/

var qrCodeReader = null;

var scanVerifiedAudio = null;
var scanFailedAudio = null;

const RAMZOR_PUBLIC_KEYS_PEM = {
  // RSA public key.
  // From https://github.com/MohGovIL/Ramzor/blob/main/Verification/RSA/RamzorQRPubKey.der.
  "IL MOH": "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4MJrQWgRnYakBsoU/eV\n" +
            "RxpvDnrGvtidQtfU0o0OGKU+p3H16ufPusBzKLHQPGAoZB33lU8wvfP01xUJTvod\n" +
            "qoi6KEKXGXC+XreQ1YJDKhIglYfPxJOOcauWf/tmV+w0xph6O3L5/2JrhxEjIbdu\n" +
            "E8zP8FvZ+KxVFA9LOFQzX7zbbiDUBLCRtIBhwtLCPIiy960O+lVZkMPXg5BrBWjc\n" +
            "NBrDN62PgOxGXvP3iF0bOlz1+m63q9cFzdKqVfOyl8jZRr3GzYD8SVSXO9EbfYId\n" +
            "8DEP+HMmqd4StD2X6OMDc9UrBBHx3nGbRpi2D9QuHA/kq/QAjQqnrd+iuzdSwQi+\n" +
            "mQIDAQAB\n" +
            "-----END PUBLIC KEY-----",

  // ECDSA public key - used for most certificates.
  // Used starting 3-Oct-2021.
  // Derived from a few signatures using https://github.com/trianglee/greenpass-derive-public-key.
  "IL MOHEC": "-----BEGIN PUBLIC KEY-----" +
              "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcw+UZUnryP4rqSw+a8xQw4wLHZkc" +
              "u4MDjJP7QeBUEpDt8xh4i4RSIBEJrBkAukSSobRDkwMb0dSCsWwK0rfMgQ==" +
              "-----END PUBLIC KEY-----",
             
  // ECDSA public key - used for "fast" medical certificates.
  // Derived from a few signatures using https://github.com/trianglee/greenpass-derive-public-key.
  "IL MOHEC_FAST": "-----BEGIN PUBLIC KEY-----\n" +
                   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc/E5MuUnnyuhwv5LTFa8clYA/B7y\n" +
                   "S5tkSWjD4E8o0yxGDT+7095mIVDo65z8yeqVRie5BGDARZYzSfJpRF+TYA==\n" +
                   "-----END PUBLIC KEY-----",

  // Old, deprecated certificates -

  // From https://github.com/MohGovIL/Ramzor/blob/main/Verification/ECDSA/RamzorQRPubKeyEC.der.
  // Was used until 2-Oct-2021.
  // "IL MOHEC": "-----BEGIN PUBLIC KEY-----\n" +
  //             "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVD+aucpFLPK3HNnaZ/T/HeFGW84a\n" +
  //             "gCBnW0Je0CzzDjhWNdNgI0R74uMhqVAiAFOH2NPjPXgQmaNSpdwRhlGXTw==\n" +
  //             "-----END PUBLIC KEY-----",
}

export function onLoad() {

  onVerifySignature();

  const TIME_BETWEEN_SUCCESSFUL_DECODES_MILLIS = 2000;
  const TIME_BETWEEN_DECODE_ATTEMPTS_MILLIS = 100;
  qrCodeReader = new ZXing.BrowserQRCodeReader(TIME_BETWEEN_SUCCESSFUL_DECODES_MILLIS);
  qrCodeReader.timeBetweenDecodingAttempts = TIME_BETWEEN_DECODE_ATTEMPTS_MILLIS;

  scanVerifiedAudio = new Audio("sounds/success.wav");
  scanFailedAudio = new Audio("sounds/access-denied.wav");
}

// Verify the QR code signature.
// Returns a "result" object.
async function verifySignature(qrCodeText) {

  var result = new Object();
  result.text = null;
  result.signedDataJson = null;

  if (qrCodeText === "") {
    return result;
  }

  try {
    const separatorIndex = qrCodeText.indexOf("#");
    const signatureBase64 = qrCodeText.substr(0, separatorIndex);
    const signedDataText = qrCodeText.substr(separatorIndex+1);

    var signedDataJson = null;
    try {
      signedDataJson = JSON.parse(signedDataText);
    } catch {
      result.text = "ERROR PARSING JSON!";
      return result;
    }

    // Decode signature from Base64.
    var signature;
    try {
      const signatureBinStr = window.atob(signatureBase64);
      signature = binaryStrToArrayBuf(signatureBinStr);
    } catch {
      result.text = "ERROR DECODING SIGNATURE!"
      return result;
    }

    // Data is signed as UTF-8, encode it as UTF-8 before verification.
    const encoder = new TextEncoder();
    var signedData = encoder.encode(signedDataText);

    var signatureType;
    if (signedDataJson.et === 1) {
      // "RSA256-like" signature type - apply SHA256 over the signed text explicitly
      // (which is also done by the verify() function below, a second time).
      signatureType = "RSA";
      signedData = await sha256DigestPromise(signedData);
    } else if (signedDataJson.et === 2) {
      // "RSA256" signature type - standard verification used, no need to perform 
      // SHA256 explicitly.
      signatureType = "RSA";
    } else if (signedDataJson.et === 3) {
      // "ECDSA NIST P-256 with SHA256 hash" signature type.
      signatureType = "ECDSA";
    } else {
      // Unknown signature type.
      result.text = "UNKNOWN SIGNATURE TYPE!";
      return result;
    }

    const publicKeyName = signedDataJson["c"];
    if (!(publicKeyName in RAMZOR_PUBLIC_KEYS_PEM)) {
      result.text = "UNKNOWN PUBLIC KEY!";
      return result;
    }
    const publicKeyPem = RAMZOR_PUBLIC_KEYS_PEM[publicKeyName];

    var signatureAlgorithm;
    var publicKey;
    if (signatureType == "RSA") {
      signatureAlgorithm = "RSASSA-PKCS1-v1_5";
      publicKey = await importRsaPublicKeyPem(publicKeyPem, "sha-256");
    } else if (signatureType == "ECDSA") {
      signatureAlgorithm = {
        name: "ECDSA",
        hash: "SHA-256",
      };
      publicKey = await importEcdsaPublicKeyPem(publicKeyPem);
      // Signature needs to be converted from DER format to IEEE P1363 format, as DER
      // is used by OpenSSL (and by Green Pass), and P1363 is used by WebCrypto.
      signature = signatureDerToP1363(signature)
    } else {
      // Unknown signature type - shouldn't happen.
      result.text = "INTERNAL ERROR!";
      return result;
    }

    // Verify public key signature over signed data.
    const signatureValid = 
      await window.crypto.subtle.verify(signatureAlgorithm, publicKey, signature, signedData);

    if (signatureValid) {
      result.text = "Signature valid"
      result.signedDataJson = signedDataJson;
    } else {
      result.text = "SIGNATURE NOT VALID!"
    }
  } catch {
    result.text = "ERROR CHECKING SIGNATURE!"
  }

  return result;
}

export async function onVerifySignature() {

  const qrCodeText = document.getElementById("qrCodeText").value;

  var qrCodeTextStripped = qrCodeText.replaceAll("\r", "").replaceAll("\n", "")

  var verifyResult = await verifySignature(qrCodeTextStripped);

  document.getElementById("verifyResult").value = verifyResult.text;

  if (verifyResult.signedDataJson != null) {
    // Signature is valid.
    document.getElementById("verifyResult").className = "validSignature";
    document.getElementById("certType").value = verifyResult.signedDataJson.ct;

    switch (verifyResult.signedDataJson.ct) {
      case 1:  // Vaccination certificate - without name
        document.getElementById("idNumber").value = verifyResult.signedDataJson.p[0].idl;
        document.getElementById("name").value = "(unknown)";
        document.getElementById("expiration").value = verifyResult.signedDataJson.p[0].e;
        break;
      case 4:   // "Fast" medical certificate
        document.getElementById("idNumber").value = verifyResult.signedDataJson.idl;
        document.getElementById("name").value = verifyResult.signedDataJson.g + " " + verifyResult.signedDataJson.f;
        document.getElementById("expiration").value = verifyResult.signedDataJson.e;
        break;
      case 2:   // Vaccination certificate - with name
      case 3:   // Recovery certificate
      case 6:   // Medical certificate
      default:  // Hope this type is valid for all other unfamiliar certificate types.
        document.getElementById("idNumber").value = verifyResult.signedDataJson.idl;
        document.getElementById("name").value = verifyResult.signedDataJson.gl + " " + verifyResult.signedDataJson.fl;
        document.getElementById("expiration").value = verifyResult.signedDataJson.e;
        break;
    }

    return true;

  } else {
    // Invalid signature.
    document.getElementById("verifyResult").className = "invalidSignature";
    document.getElementById("certType").value = "";
    document.getElementById("idNumber").value = "";
    document.getElementById("name").value = "";
    document.getElementById("expiration").value = "";

    return false;
  }
}

function displayCameraError(errorStr) {
  document.getElementById("cameraError").innerText = errorStr;
}

export function onStartScanClick() {

  displayCameraError("");

  // By default, use default camera ("environment" camera, if available).
  let cameraId = null;

  let cameraSelect = document.getElementById("cameraSelect");
  if (cameraSelect.length > 0) {
    // If user explicitly selected another camera, use it instead.
    // (-1 indicates "default camera").
    if (cameraSelect.value != -1) {
      cameraId = cameraSelect.value;
    }
  }

  qrCodeReader.decodeFromInputVideoDeviceContinuously(cameraId, 'video', onDecode).catch(onStartScanError);
}

export function onStopScanClick() {
  qrCodeReader.reset();
}

export function onSelectCameraButtonClick() {
  qrCodeReader.listVideoInputDevices().then(devices => {
    
    if (devices.length === 0) {
      displayCameraError("No cameras found!");
      return;
    }

    let cameraSelect = document.getElementById("cameraSelect");

    // Clear options list.
    while (cameraSelect.length > 0) {                
      cameraSelect.remove(0);
    }      

    // Add "default camera" option.
    var option = document.createElement("option");
    option.value = -1;
    option.text = "(Default camera)"
    cameraSelect.add (option);

    // Add all other listed cameras.
    for (const device of devices) {
      var option = document.createElement("option");
      option.value = device.deviceId;
      option.text = device.label;
      cameraSelect.add (option);
    }

    document.getElementById("cameraSelectionDiv").style.display = "block";
  });  
}

async function onDecode(result, error) {
  if (result !== null) {

    document.getElementById("qrCodeText").value = result;
    const verified = await onVerifySignature();

    if (verified) {
      scanVerifiedAudio.play();
    } else {
      scanFailedAudio.play();
    }
  }

  if (error !== null) {
    if (error instanceof ZXing.NotFoundException) {
      // QR code not found - do nothing.
    } else if (error instanceof ZXing.ChecksumException) {
      // QR code found but failed checksum validation - do nothing.
    } else if (error instanceof ZXing.FormatException) {
      // QR code found but wasn't properly formatted - do nothing.
    } else {
      displayCameraError (`Unexpected decode error (${error})`)
    }
  }
}

function onStartScanError(error) {
  displayCameraError("Error starting camera!");
}
