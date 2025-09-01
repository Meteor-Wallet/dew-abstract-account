import { test, expect } from '@playwright/test';
import globalSetup from '../global-setup.js';
import { Keypair } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';
import * as nearAPI from 'near-api-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('smart accounts can be upgraded', async () => {
    const { gasSponsor, nearJsonRpcProvider, factoryOwner } =
        await globalSetup();

    const randomSuffix = Date.now().toString().slice(-6);

    const factoryContractId = `${randomSuffix}.${factoryOwner.accountId}`;

    const wasmV1 = fs.readFileSync(
        path.join(
            __dirname,
            '../../target/near/lucis_finance_smart_account_v1/lucis_finance_smart_account_v1.wasm'
        )
    );

    const latestCodeHash = createHash('sha256')
        .update(wasmV1)
        .digest()
        .toString('base64');

    try {
        await factoryOwner.deployGlobalContract(wasmV1, 'codeHash');
    } catch (e) {
        console.log(e);
    }

    const factoryWasm = fs.readFileSync(
        path.join(
            __dirname,
            '../../target/near/lucis_finance_smart_account_factory/lucis_finance_smart_account_factory.wasm'
        )
    );

    await factoryOwner.signAndSendTransaction({
        waitUntil: 'FINAL',
        receiverId: factoryContractId,
        actions: [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(
                nearAPI.utils.format.parseNearAmount('10')
            ),
            nearAPI.transactions.deployContract(factoryWasm),
            nearAPI.transactions.functionCall(
                'new',
                {
                    owner_id: factoryOwner.accountId,
                    latest_code_hash: latestCodeHash,
                },
                150n * 10n ** 12n,
                0n
            ),
        ],
    });

    const aliceBlockchainId = 'ethereum';
    const aliceWallet = ethers.Wallet.createRandom();
    const aliceBlockchainAddress = aliceWallet.address;

    // Onboard Alice
    const aliceAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: aliceBlockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const aliceMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: aliceBlockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const aliceCreateAccountSignature = await aliceWallet.signMessage(
        aliceMessageForCreateAccount
    );

    const aliceDeadline = BigInt(
        JSON.parse(aliceMessageForCreateAccount).deadline
    );

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'create_account',
        args: {
            blockchain_id: aliceBlockchainId,
            blockchain_address: aliceBlockchainAddress,
            signature: aliceCreateAccountSignature,
            deadline: aliceDeadline.toString(),
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n, // 0.001 NEAR
    });

    // Onboard Bob
    const bobBlockchainId = 'solana';
    const bobKeypair = Keypair.generate();
    const bobBlockchainAddress = bobKeypair.publicKey.toBase58();

    const bobAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: bobBlockchainId,
            blockchain_address: bobBlockchainAddress,
        }
    );

    const bobMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: bobBlockchainId,
            blockchain_address: bobBlockchainAddress,
        }
    );

    const bobCreateAccountSignature = bs58.encode(
        nacl.sign.detached(
            new TextEncoder().encode(bobMessageForCreateAccount),
            bobKeypair.secretKey
        )
    );

    const bobDeadline = BigInt(JSON.parse(bobMessageForCreateAccount).deadline);

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'create_account',
        args: {
            blockchain_id: bobBlockchainId,
            blockchain_address: bobBlockchainAddress,
            signature: bobCreateAccountSignature,
            deadline: bobDeadline.toString(),
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n, // 0.001 NEAR
    });

    const wasmV2 = fs.readFileSync(
        path.join(
            __dirname,
            '../../target/near/lucis_finance_smart_account_v2/lucis_finance_smart_account_v2.wasm'
        )
    );

    const newCodeHash = createHash('sha256')
        .update(wasmV2)
        .digest()
        .toString('base64');

    try {
        await factoryOwner.deployGlobalContract(wasmV2, 'codeHash');
    } catch (e) {
        console.log(e);
    }

    await factoryOwner.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'update_latest_code_hash',
        args: {
            new_code_hash: newCodeHash,
        },
        gas: 100n * 10n ** 12n,
        deposit: 0n,
    });

    // Onboard Carol
    const carolBlockchainId = 'bnb';
    const carolWallet = ethers.Wallet.createRandom();
    const carolBlockchainAddress = carolWallet.address;

    const carolAccountId = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'preview_account_id',
        {
            blockchain_id: carolBlockchainId,
            blockchain_address: carolBlockchainAddress,
        }
    );

    const carolMessageForCreateAccount = await nearJsonRpcProvider.callFunction(
        factoryContractId,
        'message_for_create_account',
        {
            blockchain_id: carolBlockchainId,
            blockchain_address: carolBlockchainAddress,
        }
    );

    const carolCreateAccountSignature = await carolWallet.signMessage(
        carolMessageForCreateAccount
    );

    const carolDeadline = BigInt(
        JSON.parse(carolMessageForCreateAccount).deadline
    );

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: factoryContractId,
        methodName: 'create_account',
        args: {
            blockchain_id: carolBlockchainId,
            blockchain_address: carolBlockchainAddress,
            signature: carolCreateAccountSignature,
            deadline: carolDeadline.toString(),
        },
        gas: 100n * 10n ** 12n,
        deposit: 1n * 10n ** 21n, // 0.001 NEAR
    });

    // Current State
    const aliceContractVersion = await nearJsonRpcProvider
        .callFunction(aliceAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);

    // Alice contract should be 1.0.0 because it is created before the factory upgrade latest code hash
    expect(aliceContractVersion).toBe('1.0.0');

    const bobContractVersion = await nearJsonRpcProvider
        .callFunction(bobAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);

    // Bob contract should be 1.0.0 because it is created before the factory upgrade latest code hash
    expect(bobContractVersion).toBe('1.0.0');

    const carolContractVersion = await nearJsonRpcProvider
        .callFunction(carolAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);

    // Carol contract should be 2.0.0 because it is created after the factory upgrade latest code hash
    expect(carolContractVersion).toBe('2.0.0');

    const aliceMessageForUpgrade = await nearJsonRpcProvider.callFunction(
        aliceAccountId,
        'message_for_upgrade',
        {
            blockchain_id: aliceBlockchainId,
            blockchain_address: aliceBlockchainAddress,
        }
    );

    const aliceUpgradeSignature = await aliceWallet.signMessage(
        aliceMessageForUpgrade
    );

    await gasSponsor.callFunction({
        waitUntil: 'FINAL',
        contractId: aliceAccountId,
        methodName: 'upgrade',
        args: {
            blockchain_id: aliceBlockchainId,
            blockchain_address: aliceBlockchainAddress,
            signature: aliceUpgradeSignature,
        },
        gas: 300n * 10n ** 12n,
        deposit: 0n,
    });

    const aliceContractVersionAfterUpgrade = await nearJsonRpcProvider
        .callFunction(aliceAccountId, 'contract_source_metadata', {})
        .then((meta) => meta.version);

    // After upgrade, Alice contract should be 2.0.0
    expect(aliceContractVersionAfterUpgrade).toBe('2.0.0');

    // Bob can decide not to upgrade and stay at 1.0.0
});
