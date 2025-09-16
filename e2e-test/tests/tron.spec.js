import { test, expect } from '@playwright/test';
import globalSetup from '../global-setup.js';
import { upsertEnvVar } from '../env-editor.js';
import * as nearAPI from 'near-api-js';
import { TronWeb, utils as TronUtils } from 'tronweb';

test('onboard new tron user', async () => {
    const { factoryContractId, gasSponsor, nearJsonRpcProvider } =
        await globalSetup();

    // These values would come from the tron wallet
    const blockchainId = 'tron';
    const aliceWallet = TronUtils.accounts.generateAccount();
    const aliceBlockchainAddress = aliceWallet.address.base58;

    const tronweb = new TronWeb({
        fullHost: 'https://api.tronstack.io',
        privateKey: aliceWallet.privateKey,
    });

    // 1. Frontend will call this view function to get the account ID (can compute locally
    //    if prefer less RPC calls)
    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    // 2. Frontend will check whether the account ID already exists
    let aliceAccountExists = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExists).toBe(false);

    // 3. For best onboarding experience, if account does not exist yet, frontend SHOULD NOT ask
    //    user to sign any message.
    // 4. Frontend should show the `preview_account_id` to user and assume that it is the user
    //    smart account.
    // 5. Only when user wants to sign any transaction, the frontend should start the onboarding
    //    process.
    // 6. Frontend will call this view function to get the message that user needs to sign (can
    //    compute locally if prefer less RPC calls)
    const aliceMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: blockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    // 7. The user's wallet will handle the sign message flow, this is mocking the process

    const aliceCreateAccountSignature = await tronweb.trx.signMessageV2(
        aliceMessageForCreateAccount
    );

    // 8. Frontend pass the signature to the backend
    // 9. Backend will send the signature to the contract, sponsoring the gas fee
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

    // 10. Frontend can now use the smart account
    const aliceAccountExistsAfter = await nearJsonRpcProvider
        .viewAccount(aliceAccountId)
        .then(() => true)
        .catch(() => false);

    expect(aliceAccountExistsAfter).toBe(true);

    // This part is only for the other playwright test to function properly
    upsertEnvVar('TRON_KEY', aliceWallet.privateKey);
});

test('sign transaction', async () => {
    const { factoryContractId, gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const tronweb = new TronWeb({
        fullHost: 'https://api.tronstack.io',
        privateKey: process.env.TRON_KEY,
    });

    // These values would come from the tron wallet
    const blockchainId = 'tron';
    const aliceBlockchainAddress = tronweb.address.fromPrivateKey(
        process.env.TRON_KEY
    );

    // 1. Frontend will check whether the account ID already exists
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

    // 2. From our frontend or dApp through wallet selector, user want to sign something
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

    // 3. Frontend will call this view function to get the message that user needs to sign (can
    //    compute locally if prefer less RPC calls)
    const aliceMessageForSignTransaction =
        await nearJsonRpcProvider.callFunction(
            aliceAccountId,
            'message_for_sign_transaction',
            {
                blockchain_id: blockchainId,
                blockchain_address: aliceBlockchainAddress,
                transaction,
            }
        );

    // 4. The user's wallet will handle the sign message flow, this is mocking the process
    const aliceSignTransactionSignature = await tronweb.trx.signMessageV2(
        aliceMessageForSignTransaction
    );

    // 5. Frontend pass both the transaction and signature to the backend
    // 6. Backend will sponsor the transaction gas fee
    // 7. Optionally, backend can sponsor some NEAR too for small transaction deposits
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
                },
                200n * 10n ** 12n,
                0n
            ),
        ],
        waitUntil: 'FINAL',
    });
});
