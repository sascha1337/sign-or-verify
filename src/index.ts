import * as secp256k1 from "secp256k1";
import { bech32 } from "bech32";
import { SHA256 } from "jscrypto/SHA256";
import { RIPEMD160 } from 'jscrypto/RIPEMD160';
import { Word32Array } from 'jscrypto';
import { getChainOptions, ConnectType, WalletController, WalletStatus } from "@terra-money/wallet-provider";

const signTabButton = document.getElementById("signTabButton") as HTMLButtonElement;
const verifyTabButton = document.getElementById("verifyTabButton") as HTMLButtonElement;
const connectWalletButton = document.getElementById("connectWalletButton") as HTMLButtonElement;
const disconnectWalletButton = document.getElementById("disconnectWalletButton") as HTMLButtonElement;

const signTab = document.getElementById("signTab") as HTMLDivElement;
const verifyTab = document.getElementById("verifyTab") as HTMLDivElement;
const walletStatusDiv = document.getElementById("walletStatusDiv") as HTMLDivElement;

const messageToSignInput = document.getElementById("messageToSignInput") as HTMLTextAreaElement;
const signButton = document.getElementById("signButton") as HTMLButtonElement;
const signResultDiv = document.getElementById("signResult") as HTMLDivElement;
const signResultTextArea = document.getElementById("signResultTextArea") as HTMLTextAreaElement;

const signerInput = document.getElementById("signerInput") as HTMLInputElement;
const messageInput = document.getElementById("messageInput") as HTMLInputElement;
const signatureInput = document.getElementById("signatureInput") as HTMLInputElement;
const verifyButton = document.getElementById("verifyButton") as HTMLButtonElement;
const verifyResultDiv = document.getElementById("verifyResult") as HTMLDivElement;
const verifyResultTextArea = document.getElementById("verifyResultTextArea") as HTMLTextAreaElement;

signTabButton.addEventListener("click", () => {
  signTab.style.display = "block";
  signTabButton.disabled = true;
  verifyTab.style.display = "none";
  verifyTabButton.disabled = false;
});
verifyTabButton.addEventListener("click", () => {
  signTab.style.display = "none";
  signTabButton.disabled = false;
  verifyTab.style.display = "block";
  verifyTabButton.disabled = true;
});

(async () => {
  const chainOptions = await getChainOptions();
  const controller = new WalletController({ ...chainOptions });

  connectWalletButton.addEventListener("click", () => {
    controller.connect(ConnectType.EXTENSION);
  });
  disconnectWalletButton.addEventListener("click", () => {
    controller.disconnect();
  });

  signButton.addEventListener("click", () => {
    const msg = messageToSignInput.value;
    const msgBuffer = Buffer.from(msg, "utf8");

    // NOTE: The `signBytes` function performs SHA256 hashing, so we don't need to manually hash the msg
    controller.signBytes(msgBuffer).then((result) => {
      const signatureBytes = result.result.signature;
      const signature = Buffer.from(signatureBytes).toString("base64");

      const pubKeyJson = result.result.public_key?.toJSON();
      const pubKey = JSON.parse(pubKeyJson!).key;

      const signResult = { pubKey, signature };

      signResultDiv.style.display = "block";
      signResultTextArea.textContent = JSON.stringify(signResult, null, 2);
    });
  });

  verifyButton.addEventListener("click", () => {
    const signerPubkey = signerInput.value;
    const signerPubkeyBuffer = Buffer.from(signerPubkey, "base64");

    const msg = messageInput.value;
    const msgHash = SHA256.hash(msg).toUint8Array();
    const msgHashBuffer = Buffer.from(msgHash); // NOTE: hash is in hex encoding

    const signature = signatureInput.value;
    const signatureBuffer = Buffer.from(signature, "base64");

    const signerRawAddress = RIPEMD160.hash(SHA256.hash(new Word32Array(signerPubkeyBuffer))).toUint8Array();
    const signerAddress = bech32.encode("terra", bech32.toWords(signerRawAddress));

    const isValid = secp256k1.ecdsaVerify(signatureBuffer, msgHashBuffer, signerPubkeyBuffer);

    const verifyResult = {
      signer: signerAddress,
      signature: isValid ? "is valid ✅" : "is invalid ❌"
    };

    verifyResultDiv.style.display = "block";
    verifyResultTextArea.textContent = JSON.stringify(verifyResult, null, 2);
  });

  controller.states().subscribe(async (states) => {
    if (states.status === WalletStatus.WALLET_NOT_CONNECTED) {
      signButton.disabled = true;
      connectWalletButton.disabled = false;
      disconnectWalletButton.disabled = true;
      walletStatusDiv.textContent = "Wallet is not connected!";
    } else if (states.status === WalletStatus.WALLET_CONNECTED) {
      const wallet = states.wallets[0]!;
      signButton.disabled = false;
      connectWalletButton.disabled = true;
      disconnectWalletButton.disabled = false;
      walletStatusDiv.textContent = "Wallet connected! Address: " + wallet.terraAddress;
    }
  })
})();
