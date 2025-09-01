import fs from 'fs';
import path from 'path';
import * as nearAPI from 'near-api-js';
import { createHash } from 'crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { upsertEnvVar } from './env-editor';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ quiet: true });

export default async () => {
    const provider = process.env.FASTNEAR_API_KEY
        ? new nearAPI.providers.JsonRpcProvider({
              url: 'https://test.rpc.fastnear.com',
              headers: {
                  Authorization: `Bearer ${process.env.FASTNEAR_API_KEY}`,
              },
          })
        : new nearAPI.providers.JsonRpcProvider({
              url: 'https://rpc.testnet.near.org',
          });

    const masterAccountId = process.env.NEAR_MASTER_ACCOUNT;
    const masterPrivateKey = process.env.NEAR_MASTER_KEY;

    if (!masterAccountId || !masterPrivateKey) {
        throw new Error('Set NEAR_MASTER_ACCOUNT and NEAR_MASTER_KEY env vars');
    }

    const keyPair = nearAPI.KeyPair.fromString(masterPrivateKey);
    const signer = new nearAPI.KeyPairSigner(keyPair);

    const masterAccount = new nearAPI.Account(
        masterAccountId,
        provider,
        signer
    );

    const factoryAccountId = process.env.FACTORY_ACCOUNT_ID;

    if (factoryAccountId) {
        return {
            factoryContractId: factoryAccountId,
            gasSponsor: masterAccount,
            factoryOwner: masterAccount,
            nearJsonRpcProvider: provider,
        };
    }

    const randomSuffix = Date.now().toString().slice(-6);

    const newFactoryAccountId = `${randomSuffix}.${masterAccountId}`;

    const wasmV1 = fs.readFileSync(
        path.join(
            __dirname,
            '../target/near/lucis_finance_smart_account_v1/lucis_finance_smart_account_v1.wasm'
        )
    );

    const latestCodeHash = createHash('sha256')
        .update(wasmV1)
        .digest()
        .toString('base64');

    try {
        await masterAccount.deployGlobalContract(wasmV1, 'codeHash');
    } catch (e) {
        console.log(e);
    }

    const factoryWasm = fs.readFileSync(
        path.join(
            __dirname,
            '../target/near/lucis_finance_smart_account_factory/lucis_finance_smart_account_factory.wasm'
        )
    );

    await masterAccount.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: newFactoryAccountId,
        actions: [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(
                nearAPI.utils.format.parseNearAmount('10')
            ),
            nearAPI.transactions.deployContract(factoryWasm),
            nearAPI.transactions.functionCall(
                'new',
                {
                    owner_id: masterAccountId,
                    latest_code_hash: latestCodeHash,
                },
                150n * 10n ** 12n,
                0n
            ),
        ],
    });

    upsertEnvVar('FACTORY_ACCOUNT_ID', newFactoryAccountId);

    return {
        factoryContractId: newFactoryAccountId,
        gasSponsor: masterAccount,
        factoryOwner: masterAccount,
        nearJsonRpcProvider: provider,
    };
};
