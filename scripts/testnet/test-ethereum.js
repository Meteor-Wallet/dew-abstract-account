import * as nearAPI from 'near-api-js';
import { JsonRpcProvider } from 'near-api-js/lib/providers/index.js';
import fs from 'fs';
import 'dotenv/config';
import bs58 from 'bs58';
import { createHash } from 'crypto';
import { ethers } from 'ethers';

async function main() {
    const masterAccountId = process.env.MASTER_ACCOUNT_ID;
    const masterPrivateKey = process.env.MASTER_PRIVATE_KEY;
    const wasmFilePath = '../../target/near/near_recovery/near_recovery.wasm';

    const wasmCode = fs.readFileSync(wasmFilePath);
    const codeHash = bs58.encode(
        createHash('sha256').update(wasmCode).digest()
    );

    const jsonRpcProvider = new JsonRpcProvider({
        url: 'https://rpc.testnet.near.org',
    });

    const masterAccount = new nearAPI.Account(
        masterAccountId,
        jsonRpcProvider,
        new nearAPI.KeyPairSigner(nearAPI.KeyPair.fromString(masterPrivateKey))
    );

    const blockchainId = 'ethereum';
    const ethWallet = ethers.Wallet.createRandom();
    const blockchainAddress = ethWallet.address.toLowerCase();

    const testAccountId = `${blockchainAddress}.${masterAccountId}`;

    const createAccountOutcome = await masterAccount.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: testAccountId,
        actions: [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(10n ** 22n),
            {
                useGlobalContract: {
                    contractIdentifier: {
                        CodeHash: bs58.decode(codeHash),
                    },
                },
            },
            nearAPI.transactions.functionCall(
                'init',
                {
                    blockchain_id: blockchainId,
                    blockchain_address: blockchainAddress,
                },
                50n * 10n ** 12n, // 50 Tgas
                0n
            ),
        ],
    });

    console.log(
        `Create account: https://testnet.nearblocks.io/txns/${createAccountOutcome.transaction.hash}`
    );

    /** @type {import('near-wallet-selector/lib/esm/wallets/Wallet').SignAndSendTransactionParams} */
    const transaction = {
        receiverId: 'wrap.testnet',
        actions: [
            {
                type: 'FunctionCall',
                params: {
                    methodName: 'storage_deposit',
                    args: {
                        account_id: testAccountId,
                        registration_only: true,
                    },
                    gas: '50000000000000',
                    deposit: '1250000000000000000000',
                },
            },
            {
                type: 'FunctionCall',
                params: {
                    methodName: 'near_deposit',
                    args: {},
                    gas: '50000000000000',
                    deposit: '1000000000000000000000',
                },
            },
            {
                type: 'FunctionCall',
                params: {
                    methodName: 'ft_transfer',
                    args: {
                        receiver_id: masterAccountId,
                        amount: '1000000000000000000000',
                    },
                    gas: '50000000000000',
                    deposit: '1',
                },
            },
        ],
    };

    const message = await jsonRpcProvider.callFunction(
        testAccountId,
        'message_for_sign_transaction',
        {
            blockchain_id: blockchainId,
            blockchain_address: blockchainAddress,
            transaction,
        }
    );

    const signature = await ethWallet.signMessage(message);

    const signTransactionOutcome = await masterAccount.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: testAccountId,
        actions: [
            nearAPI.transactions.functionCall(
                'sign_transaction',
                {
                    blockchain_id: blockchainId,
                    blockchain_address: blockchainAddress,
                    transaction,
                    signature,
                },
                300n * 10n ** 12n,
                0n
            ),
        ],
    });

    console.log(
        `Sign transaction: https://testnet.nearblocks.io/txns/${signTransactionOutcome.transaction.hash}`
    );
}

main();
