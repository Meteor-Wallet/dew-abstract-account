import { test, expect } from '@playwright/test';
import globalSetup from '../global-setup.js';
import { upsertEnvVar } from '../env-editor.js';
import * as nearAPI from 'near-api-js';
import bitcoin from 'bitcoinjs-lib';
import bitcoinMessage from 'bitcoinjs-message';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

const ECPair = ECPairFactory(ecc);

test('onboard new btc user', async () => {
    const { factoryContractId, gasSponsor, nearJsonRpcProvider } =
        await globalSetup();

    // These values would come from the btc wallet
    const blockchainId = 'btc';
    const aliceKeypair = ECPair.makeRandom({
        network: bitcoin.networks.bitcoin,
    });

    // Public key should be sent as hex string
    const aliceBlockchainAddress = bitcoin.payments.p2pkh({
        pubkey: Buffer.from(aliceKeypair.publicKey),
        network: bitcoin.networks.bitcoin,
    }).address;

    // 1. Frontend will call this view function to get the account ID
    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    // 2. Check whether the account ID already exists
    let aliceAccountExists = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExists).toBe(false);

    // 6. Get the message to sign
    const aliceMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    // 7. Sign with Ed25519 secret key, encode as base64
    const sigBytes = bitcoinMessage.sign(
        aliceMessageForCreateAccount,
        aliceKeypair.privateKey,
        aliceKeypair.compressed,
        { network: bitcoin.networks.bitcoin }
    );
    const aliceCreateAccountSignature = sigBytes.toString('base64');

    // 9. Backend will send the signature to the contract
    const deadline = BigInt(JSON.parse(aliceMessageForCreateAccount).deadline);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'create_account',
        args: {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
            signature: aliceCreateAccountSignature,
            deadline: deadline.toString(),
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n, // 0.001 NEAR
    });

    // 10. Verify account created
    const aliceAccountExistsAfter = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExistsAfter).toBe(true);

    // Persist secret key for the next test
    upsertEnvVar('BTC_KEY', aliceKeypair.toWIF());
});

test('sign transaction', async () => {
    const { factoryContractId, gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const blockchainId = 'btc';

    // Create keypair object from secret key
    const aliceKeypair = ECPair.fromWIF(
        process.env.BTC_KEY,
        bitcoin.networks.bitcoin
    );

    // Public key in hex
    const aliceBlockchainAddress = bitcoin.payments.p2pkh({
        pubkey: Buffer.from(aliceKeypair.publicKey),
        network: bitcoin.networks.bitcoin,
    }).address;

    // 1. Get accountId
    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    let aliceAccountExists = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExists).toBe(true);

    // 2. Build transaction
    /** @type {import('near-wallet-selector/lib/esm/wallets/Wallet').SignAndSendTransactionParams} */
    const transaction = {
        receiverId: 'wrap.testnet',
        actions: [
            {
                type: 'FunctionCall',
                params: {
                    methodName: 'storage_deposit',
                    args: {
                        account_id: aliceAccountId,
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
                    deposit: '1000',
                },
            },
            {
                type: 'FunctionCall',
                params: {
                    methodName: 'ft_transfer',
                    args: {
                        receiver_id: factoryOwner.accountId,
                        amount: '1000',
                    },
                    gas: '50000000000000',
                    deposit: '1',
                },
            },
        ],
    };

    // 3. Get message to sign
    const aliceMessageForSignTransaction =
        await nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'blind_message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: aliceBlockchainAddress,
                transaction,
            }
        );

    // 4. Sign message, encode base64
    const sigBytes = bitcoinMessage.sign(
        aliceMessageForSignTransaction,
        aliceKeypair.privateKey,
        aliceKeypair.compressed,
        { network: bitcoin.networks.bitcoin }
    );
    const aliceSignTransactionSignature = sigBytes.toString('base64');

    // 5. Send transaction with signature
    await gasSponsor.signAndSendTransaction({
        receiverId: aliceAccountId,
        actions: [
            nearAPI.transactions.transfer(10n ** 23n), // 0.1 NEAR
            nearAPI.transactions.functionCall(
                'sign_transaction',
                {
                    blockchain_id: blockchainId,
                    blockchain_address: aliceBlockchainAddress,
                    transaction,
                    signature: aliceSignTransactionSignature,
                    blind_message: true,
                },
                200n * 10n ** 12n,
                0n
            ),
        ],
        waitUntil: 'FINAL',
    });
});
