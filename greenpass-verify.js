'use strict';


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

function onLoad() {

  const RAMZOR_QR_PUBLIC_KEY_RSA_PEM = 
    "-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4MJrQWgRnYakBsoU/eV\n" +
    "RxpvDnrGvtidQtfU0o0OGKU+p3H16ufPusBzKLHQPGAoZB33lU8wvfP01xUJTvod\n" +
    "qoi6KEKXGXC+XreQ1YJDKhIglYfPxJOOcauWf/tmV+w0xph6O3L5/2JrhxEjIbdu\n" +
    "E8zP8FvZ+KxVFA9LOFQzX7zbbiDUBLCRtIBhwtLCPIiy960O+lVZkMPXg5BrBWjc\n" +
    "NBrDN62PgOxGXvP3iF0bOlz1+m63q9cFzdKqVfOyl8jZRr3GzYD8SVSXO9EbfYId\n" +
    "8DEP+HMmqd4StD2X6OMDc9UrBBHx3nGbRpi2D9QuHA/kq/QAjQqnrd+iuzdSwQi+\n" +
    "mQIDAQAB\n" +
    "-----END PUBLIC KEY-----";

  const RAMZOR_QR_PUBLIC_KEY_EC_PEM = 
    "-----BEGIN PUBLIC KEY-----\n" +
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVD+aucpFLPK3HNnaZ/T/HeFGW84a\n" +
    "gCBnW0Je0CzzDjhWNdNgI0R74uMhqVAiAFOH2NPjPXgQmaNSpdwRhlGXTw==\n" +
    "-----END PUBLIC KEY-----"

  document.getElementById("pemRsaPublicKey").value = RAMZOR_QR_PUBLIC_KEY_RSA_PEM;
  document.getElementById("pemEcPublicKey").value = RAMZOR_QR_PUBLIC_KEY_EC_PEM;
  onVerifySignature();

  const TIME_BETWEEN_SUCCESSFUL_DECODES_MILLIS = 2000;
  const TIME_BETWEEN_DECODE_ATTEMPTS_MILLIS = 100;
  qrCodeReader = new ZXing.BrowserQRCodeReader(TIME_BETWEEN_SUCCESSFUL_DECODES_MILLIS);
  qrCodeReader.timeBetweenDecodingAttempts = TIME_BETWEEN_DECODE_ATTEMPTS_MILLIS;

  scanVerifiedAudio = new Audio("sounds/success.wav");
  scanFailedAudio = new Audio("sounds/access-denied.wav");
}

// Verify the QR code signature using the public key.
// Returns a "result" object.
async function verifySignature(qrCodeText, pemRsaPublicKey, pemEcPublicKey) {

  var result = new Object();
  result.text = null;
  result.signedDataJson = null;

  var signedDataJson = null;

  try {
    const separatorIndex = qrCodeText.indexOf("#");
    const signatureBase64 = qrCodeText.substr(0, separatorIndex);
    const signedDataText = qrCodeText.substr(separatorIndex+1);

    signedDataJson = JSON.parse(signedDataText);

    // Decode signature from Base64.
    const signatureBinStr = window.atob(signatureBase64);
    var signature = binaryStrToArrayBuf(signatureBinStr);

    var signedData = binaryStrToArrayBuf(signedDataText);

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

    var signatureAlgorithm;
    var publicKey;
    if (signatureType == "RSA") {
      signatureAlgorithm = "RSASSA-PKCS1-v1_5";
      publicKey = await importRsaPublicKeyPem(pemRsaPublicKey, "sha-256");
    } else if (signatureType == "ECDSA") {
      signatureAlgorithm = {
        name: "ECDSA",
        hash: "SHA-256",
      };
      publicKey = await importEcdsaPublicKeyPem(pemEcPublicKey);
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

async function onVerifySignature() {

  const qrCodeText = document.getElementById("qrCodeText").value;
  const pemRsaPublicKey = document.getElementById("pemRsaPublicKey").value;
  const pemEcPublicKey = document.getElementById("pemEcPublicKey").value;

  var qrCodeTextStripped = qrCodeText.replaceAll("\r", "").replaceAll("\n", "")

  var verifyResult = await verifySignature(qrCodeTextStripped, pemRsaPublicKey, pemEcPublicKey);

  document.getElementById("verifyResult").value = verifyResult.text;

  if (verifyResult.signedDataJson != null) {
    // Signature is valid.
    document.getElementById("verifyResult").className = "validSignature";
    document.getElementById("idNumber").value = verifyResult.signedDataJson.p[0].idl;
    document.getElementById("expiration").value = verifyResult.signedDataJson.p[0].e;

    return true;

  } else {
    // Invalid signature.
    document.getElementById("verifyResult").className = "invalidSignature";
    document.getElementById("idNumber").value = "";
    document.getElementById("expiration").value = "";

    return false;
  }
}

function displayCameraError(errorStr) {
  document.getElementById("cameraError").innerText = errorStr;
}

function onStartScanClick() {

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

function onStopScanClick() {
  qrCodeReader.reset();
}

function onSelectCameraButtonClick() {
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
