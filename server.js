import express from 'express';
import cors from 'cors';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const app = express();
const port = 3001; // Backend runs on a different port than frontend

// --- CONFIGURATION (MUST CHANGE FOR YOUR SETUP) ---
// Relying Party Name - The name of your application
const rpName = 'SimpleWebAuthn Example';
// Relying Party ID - The domain name where your site is hosted
const rpID = 'localhost'; // CHANGE THIS for production or testing with your domain
// Origin - The exact URL where your frontend is running
const expectedOrigin = `http://localhost:5173`; // CHANGE THIS (especially HTTP/HTTPS and port)

if (rpID === 'localhost' && !expectedOrigin.startsWith('http://localhost')) {
    console.warn('WARN: rpID is localhost, but origin is not. This might fail in some browsers!');
}
if (!rpID === 'localhost' && !expectedOrigin.startsWith('https://')) {
     console.warn('WARN: rpID is not localhost, but origin is not HTTPS. This WILL fail WebAuthn!');
}
// --- END CONFIGURATION ---


// --- VERY Simple In-Memory Storage (NOT FOR PRODUCTION!) ---
const userStore = {}; // { username: { id: string, username: string, currentChallenge?: string } }
const credentialStore = {}; // { username: Authenticator[] } - In reality, store in DB linked to user ID

app.use(cors({ // Allow requests from your frontend development server
    origin: expectedOrigin,
    credentials: true,
}));
app.use(express.json());

// --- Registration Routes ---

app.post('/generate-registration-options', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).send({ error: 'Username is required' });
    }

    // Simple user "creation" or lookup
    let user = userStore[username];
    if (!user) {
        const userId = `user_${Date.now()}_${Math.random().toString(16).slice(2)}`;
        user = { id: userId, username };
        userStore[username] = user;
        credentialStore[username] = [];
        console.log(`Created user: ${username} (ID: ${userId})`);
    }

     // Prevent reusing credentials for different users in this simple store
    const existingCredentials = credentialStore[username] || [];

   // Inside the try block of app.post('/generate-registration-options', ...)

try {
    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        // Convert the user ID string to a Buffer using UTF-8 encoding
        userID: Buffer.from(user.id, 'utf8'), // <<< FIX IS HERE
        userName: user.username, // userName can usually remain a string
        attestationType: 'none',
        // Ensure the previous fix for excludeCredentials is also present
        excludeCredentials: existingCredentials.map(cred => ({
            id: isoBase64URL.toBuffer(cred.credentialID),
            type: 'public-key',
            transports: cred.transports,
        })),
         authenticatorSelection: {
            residentKey: 'preferred',
            requireResidentKey: false,
            userVerification: 'preferred',
        },
    });

    // Store the challenge (challenge is usually a string, no change needed here)
    userStore[username].currentChallenge = options.challenge;
    console.log(`Generated registration options for ${username}:`, options);

    res.send(options);

} catch (error) {
    console.error('Failed to generate registration options:', error);
    res.status(500).send({ error: 'Failed to generate registration options' });
}
});

app.post('/verify-registration', async (req, res) => {
    const { username, credential } = req.body;

    if (!username || !credential) {
        return res.status(400).send({ error: 'Username and credential are required' });
    }

    const user = userStore[username];
    if (!user || !user.currentChallenge) {
        return res.status(400).send({ error: 'User not found or no registration challenge pending' });
    }

    try {
        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: user.currentChallenge,
            expectedOrigin,
            expectedRPID: rpID,
            requireUserVerification: false, // Set based on your policy / authenticatorSelection
        });

        const { verified, registrationInfo } = verification;

        if (verified && registrationInfo) {
             console.log(`Registration verified for ${username}. Info:`, registrationInfo);
            const { credentialPublicKey, credentialID, counter } = registrationInfo;

             // Check if this credential ID already exists for *any* user (simple prevention)
             const exists = Object.values(credentialStore).flat().some(cred => cred.credentialID === credentialID);
             if(exists) {
                 return res.status(400).send({error: 'Credential already registered.'});
             }
             console.log(typeof credentialID)
            // Store the new credential (convert Buffers to base64url for JSON compatibility)
            const newCredential = {
                credentialID: isoBase64URL.fromBuffer(credentialID), // Store as base64url string
                credentialPublicKey: isoBase64URL.fromBuffer(credentialPublicKey), // Store as base64url string
                counter,
                transports: credential.response.transports, // Store transports if available
            };
            credentialStore[username].push(newCredential);

            console.log(`Stored credential for ${username}:`, newCredential.credentialID);

            // Clear the challenge
            delete userStore[username].currentChallenge;

            res.send({ verified: true });
        } else {
            console.error(`Registration verification failed for ${username}:`, verification);
            res.status(400).send({ error: 'Registration verification failed' });
        }
    } catch (error) {
        console.error(`Error verifying registration for ${username}:`, error);
         // Clear the challenge on error too
        if (userStore[username]) delete userStore[username].currentChallenge;
        res.status(500).send({ error: error.message });
    }
});


// --- Authentication Routes ---

app.post('/generate-authentication-options', async (req, res) => {
     const { username } = req.body;

    if (!username) {
        return res.status(400).send({ error: 'Username is required' });
    }

    const user = userStore[username];
     const userCredentials = credentialStore[username] || [];

    if (!user || userCredentials.length === 0) {
        return res.status(400).send({ error: 'User not found or no credentials registered' });
    }

    try {
        const options = await generateAuthenticationOptions({
            rpID,
            // Allow users to select any of their registered credentials
            allowCredentials: userCredentials.map(cred => ({
                id: isoBase64URL.toBuffer(cred.credentialID), // Convert back to Buffer
                type: 'public-key',
                transports: cred.transports,
            })),
            userVerification: 'preferred', // Prefer user verification
        });

         // Temporarily store the challenge
        userStore[username].currentChallenge = options.challenge;
         console.log(`Generated authentication options for ${username}:`, options);

        res.send(options);
    } catch (error) {
         console.error('Failed to generate authentication options:', error);
         res.status(500).send({ error: 'Failed to generate authentication options' });
    }
});

app.post('/verify-authentication', async (req, res) => {
     const { username, credential } = req.body; // credential is the AssertionCredential

     if (!username || !credential) {
         return res.status(400).send({ error: 'Username and credential are required' });
     }

     const user = userStore[username];
     const userCredentials = credentialStore[username] || [];

    if (!user || !user.currentChallenge) {
        return res.status(400).send({ error: 'User not found or no authentication challenge pending' });
    }

    // Find the credential being used for login
     const credentialID_b64url = isoBase64URL.fromBuffer(credential.rawId); // Get ID from assertion
     const storedCredential = userCredentials.find(cred => cred.credentialID === credentialID_b64url);

    if (!storedCredential) {
        return res.status(400).send({ error: 'Credential not recognized for this user' });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: user.currentChallenge,
            expectedOrigin,
            expectedRPID: rpID,
            authenticator: { // Provide the stored credential info for verification
                 credentialID: isoBase64URL.toBuffer(storedCredential.credentialID), // Convert back to buffer
                 credentialPublicKey: isoBase64URL.toBuffer(storedCredential.credentialPublicKey), // Convert back to buffer
                 counter: storedCredential.counter,
                 transports: storedCredential.transports,
            },
            requireUserVerification: false, // Set according to your policy
        });

        const { verified, authenticationInfo } = verification;

        if (verified) {
             console.log(`Authentication verified for ${username}. Info:`, authenticationInfo);
            // Update the credential counter
            storedCredential.counter = authenticationInfo.newCounter;
             console.log(`Updated counter for credential ${storedCredential.credentialID} to ${authenticationInfo.newCounter}`);

            // Clear the challenge
            delete userStore[username].currentChallenge;

            // *** LOGIN SUCCESSFUL ***
            // In a real app: Create a session, issue a JWT, etc.
            res.send({ verified: true, username: user.username });

        } else {
            console.error(`Authentication verification failed for ${username}:`, verification);
            res.status(400).send({ error: 'Authentication verification failed' });
        }
    } catch (error) {
        console.error(`Error verifying authentication for ${username}:`, error);
        // Clear the challenge on error too
        if (userStore[username]) delete userStore[username].currentChallenge;
        res.status(500).send({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Backend server listening on port ${port}`);
    console.log(`Configuration: rpID='${rpID}', expectedOrigin='${expectedOrigin}'`);
});