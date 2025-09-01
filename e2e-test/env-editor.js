import fs from 'fs';
import dotenv from 'dotenv';

const ENV_PATH = '.env';

export function upsertEnvVar(key, value) {
    let envContent = '';
    if (fs.existsSync(ENV_PATH)) {
        envContent = fs.readFileSync(ENV_PATH, 'utf-8');
    }

    const regex = new RegExp(`^${key}=.*$`, 'm');

    if (regex.test(envContent)) {
        // Replace existing
        envContent = envContent.replace(regex, `${key}=${value}`);
    } else {
        // Append
        if (!envContent.endsWith('\n') && envContent.length > 0) {
            envContent += '\n';
        }
        envContent += `${key}=${value}\n`;
    }

    fs.writeFileSync(ENV_PATH, envContent, 'utf-8');
    dotenv.config({ quiet: true }); // Reload env vars
}
