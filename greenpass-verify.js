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


/*** Crypto ***/

// Import an RSA public key (PEM format).
// Key is imported with the specified hashing algorithm and as RSASSA-PKCS1-v1_5,
// for signature verification only.
function importRsaPublicKeyPem(pemText, hashAlgorithm) {

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


/*** Main ***/

var html5QrCode = null;

function onLoad() {

  const RAMZOR_QR_PUBLIC_KEY_PEM = 
    "-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4MJrQWgRnYakBsoU/eV\n" +
    "RxpvDnrGvtidQtfU0o0OGKU+p3H16ufPusBzKLHQPGAoZB33lU8wvfP01xUJTvod\n" +
    "qoi6KEKXGXC+XreQ1YJDKhIglYfPxJOOcauWf/tmV+w0xph6O3L5/2JrhxEjIbdu\n" +
    "E8zP8FvZ+KxVFA9LOFQzX7zbbiDUBLCRtIBhwtLCPIiy960O+lVZkMPXg5BrBWjc\n" +
    "NBrDN62PgOxGXvP3iF0bOlz1+m63q9cFzdKqVfOyl8jZRr3GzYD8SVSXO9EbfYId\n" +
    "8DEP+HMmqd4StD2X6OMDc9UrBBHx3nGbRpi2D9QuHA/kq/QAjQqnrd+iuzdSwQi+\n" +
    "mQIDAQAB\n" +
    "-----END PUBLIC KEY-----";

  document.getElementById("pemPublicKey").value = RAMZOR_QR_PUBLIC_KEY_PEM;

  onVerifySignature();
}

// Verify the QR code signature using the public key.
// Returns a "result" object.
async function verifySignature(qrCodeText, pemPublicKey) {

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
    const signature = binaryStrToArrayBuf(signatureBinStr);
  
    // Calculate SHA256 of signed text.
    var signedData = binaryStrToArrayBuf(signedDataText);

    if (signedDataJson.et === 1) {
      // "RSA256-like" signature type - apply SHA256 over the signed text explicitly
      // (which is also done by the verify() function below, a second time).
      signedData = await sha256DigestPromise(signedData);
    } else if (signedDataJson.et === 2) {
      // "RSA256" signature type - standard verification used, no need to perform 
      // SHA256 explicitly.
    } else {
      // Unknown signature type.
      result.text = "UNKNOWN SIGNATURE TYPE!";
      return result;
    }
  
    // Import public key.
    const publicKey = await importRsaPublicKeyPem(pemPublicKey, "sha-256");
    
    // Verify public key signature over signed data.
    const signatureValid = 
      await window.crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signedData);

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
  const pemPublicKey = document.getElementById("pemPublicKey").value;

  var verifyResult = await verifySignature(qrCodeText, pemPublicKey);

  document.getElementById("verifyResult").value = verifyResult.text;

  if (verifyResult.signedDataJson != null) {
    // Signature is valid.
    document.getElementById("verifyResult").className = "validSignature";
    document.getElementById("idNumber").value = verifyResult.signedDataJson.p[0].idl;
    document.getElementById("expiration").value = verifyResult.signedDataJson.p[0].e;

  } else {
    // Invalid signature.
    document.getElementById("verifyResult").className = "invalidSignature";
    document.getElementById("idNumber").value = "";
    document.getElementById("expiration").value = "";
  }
}

function onStartScanClick() {
  document.getElementById("reader").style.display = "block";

  html5QrCode = new Html5Qrcode("reader", /* verbose= */ false);
  const config = { fps: 10, qrbox: 250 };

  html5QrCode.start(
    { facingMode: "environment" }, 
    config, 
    onScanSuccess, 
    onScanError)
  .catch(onScanStartError);
}

function onStopScanClick() {
  if (html5QrCode !== null)  {
    html5QrCode.stop();
    html5QrCode = null;

    document.getElementById("reader").style.display = "none";
  }
}

function onScanSuccess(qrMessage) {
  document.getElementById("qrCodeText").value = qrMessage;
}

function onScanError(errorMessage) {
  // Do nothing.
}

function onScanStartError(errorMessage) {
  console.log(`Error starting camera ('${errorMessage}').`);
}
