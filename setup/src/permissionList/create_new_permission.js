import { bcs } from "@mysten/sui/bcs";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { SuiClient } from "@mysten/sui/client";
import { toB64 } from "@mysten/sui/utils"; // Import toB64 utility
import dotenv from "dotenv";

dotenv.config();

const MNEMONIC =
  "acoustic mango victory near beach machine hand lecture night broccoli media name";

async function getWalletKeypair() {
  try {
    const keypair = Ed25519Keypair.deriveKeypair(MNEMONIC);
    return keypair;
  } catch (error) {
    console.error("Error deriving keypair:", error);
    throw error;
  }
}

async function getSigner() {
  const keypair = await getWalletKeypair();
  return keypair;
}

async function getWalletAddress() {
  const keypair = await getWalletKeypair();
  const address = keypair.toSuiAddress();
  console.log("Wallet Address:", address);
  return address;
}

async function getWalletBalance() {
  try {
    const client = new SuiClient({ url: "https://fullnode.testnet.sui.io" });
    const address = await getWalletAddress();
    const balance = await client.getBalance({ owner: address });

    console.log("Wallet Balance:", balance.totalBalance, "SUI");
    return balance;
  } catch (error) {
    console.error("Error fetching balance:", error);
    throw error;
  }
}

const suiClient = new SuiClient({
  url: "https://fullnode.testnet.sui.io",
});

async function create_permission_object() {
  try {
    const tx = new Transaction();
    const signer = await getSigner();
    const sender = signer.toSuiAddress(); // Corrected to get address from signer

    const packageID = process.env.PACKAGE_ID?.toString() || "";
    const portraitType = "some_type"; // Define the correct type

    tx.moveCall({
      target: `${packageID}::shareobject::create_permission`,
      arguments: [
        tx.pure.vector("string", ["permission1"]),
        tx.pure.address("0x9f84c25749332ad30967af149ab72880480090c1088e700aa8012148e844c955"),
      ]
    });

    tx.setSender(sender);
    tx.setGasBudget(500000000);

    const transactionBytes = await tx.build({ client: suiClient });
    const signature = await signer.signTransaction(transactionBytes);

    const result = await suiClient.executeTransactionBlock({
      transactionBlock: toB64(transactionBytes),
      signature: signature.signature,
      options: {
        showEffects: true,
      },
    });

    if (result.effects?.status?.error) {
      throw new Error(`Error during mint_and_transfer: ${result.effects?.status?.error}`);
    }

    console.log("Transaction executed successfully:", result);
  } catch (error) {
    console.error("Error creating permission object:", error);
  }
}

// Run functions
getWalletBalance();
create_permission_object();
