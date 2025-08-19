import * as nearAPI from 'near-api-js';
import { JsonRpcProvider } from 'near-api-js/lib/providers/index.js';
import fs from 'fs';
import 'dotenv/config';
import bs58 from 'bs58';
import { createHash } from 'crypto';

async function main() {
    const masterAccountId = process.env.MASTER_ACCOUNT_ID;
    const masterPrivateKey = process.env.MASTER_PRIVATE_KEY;
    const wasmFilePath = '../../target/near/near_recovery.wasm';

    const jsonRpcProvider = new JsonRpcProvider({
        url: 'https://rpc.testnet.near.org',
    });

    const masterAccount = new nearAPI.Account(
        masterAccountId,
        jsonRpcProvider,
        new nearAPI.KeyPairSigner(nearAPI.KeyPair.fromString(masterPrivateKey))
    );

    const wasmCode = fs.readFileSync(wasmFilePath);
    const codeHash = bs58.encode(
        createHash('sha256').update(wasmCode).digest()
    );

    console.log(`Deploying global contract with code hash: ${codeHash}`);

    const deployGlobalContractOutcome =
        await masterAccount.deployGlobalContract(wasmCode, 'codeHash');

    console.log(
        `Global contract deployed successfully: ${deployGlobalContractOutcome.transaction.hash}`
    );
}

main();
