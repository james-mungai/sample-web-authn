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
             console.log(`Registration verified for ${username}.`); 
             // Correctly extract nested credential info
             const { id: credentialIDString, publicKey: credentialPublicKeyBytes, counter } = registrationInfo.credential;

             // Ensure credential store array exists for the user
             if (!credentialStore[username]) {
                 credentialStore[username] = [];
             }

             // Check if this credential ID already exists for *any* user
             const exists = Object.values(credentialStore).flat().some(cred => cred.credentialID === credentialIDString);
             if(exists) {
                 console.warn(`Credential ID ${credentialIDString} already registered.`);
                 return res.status(400).send({error: 'Credential already registered.'});
             }

            // Store the new credential using the Base64URL string ID
            console.log(`DEBUG: Extracted public key bytes (type: ${typeof credentialPublicKeyBytes}):`, credentialPublicKeyBytes);
            const newCredential = {
                credentialID: credentialIDString, // Store the ID string directly
                credentialPublicKey: isoBase64URL.fromBuffer(credentialPublicKeyBytes), // Store public key as base64url string
                counter,
                // Ensure transports is captured, provide default if necessary
                transports: registrationInfo.credential.transports || credential.response.transports || [],
            };
            credentialStore[username].push(newCredential);

            console.log(`Stored credential for ${username}: ID = ${newCredential.credentialID}`);

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
            // Pass the credential ID STRING directly; the library handles conversion.
            allowCredentials: userCredentials.map(cred => ({
                id: cred.credentialID, // Pass the stored Base64URL string ID
                type: 'public-key',
                // Ensure transports is an array, provide default if missing or incorrect type
                transports: Array.isArray(cred.transports) ? cred.transports : undefined,
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

     console.log(`\n--- Verify Authentication Attempt ---`);
     console.log(`Username: ${username}`);
     console.log(`Received Credential Object (Assertion):`, JSON.stringify(credential, null, 2)); // Log the full assertion

     if (!username || !credential) {
         return res.status(400).send({ error: 'Username and credential are required' });
     }

     const user = userStore[username];
     const userCredentials = credentialStore[username] || [];

     console.log(`Stored Credentials for ${username}:`, JSON.stringify(userCredentials, null, 2));

    if (!user || !user.currentChallenge) {
        return res.status(400).send({ error: 'User not found or no authentication challenge pending' });
    }

    // The browser extension seems to send rawId already encoded as Base64URL string in the JSON
    const credentialID_b64url = credential.rawId;
    console.log(`Using credentialID from assertion.rawId directly: ${credentialID_b64url}`);

     const storedCredential = userCredentials.find(cred => cred.credentialID === credentialID_b64url);

    if (!storedCredential) {
        console.error(`Could not find stored credential matching ID: ${credentialID_b64url}`);
        return res.status(400).send({ error: 'Credential not recognized for this user' });
    }

    console.log(`Found matching stored credential:`, JSON.stringify(storedCredential, null, 2));

    // Prepare the authenticator object for the library
    let authenticatorDataForLib;
    try {
        const credentialIDBuffer = isoBase64URL.toBuffer(storedCredential.credentialID);
        const credentialPublicKeyBuffer = isoBase64URL.toBuffer(storedCredential.credentialPublicKey);

        console.log(`DEBUG: Converted credentialID to Buffer (length: ${credentialIDBuffer?.length})`);
        console.log(`DEBUG: Converted credentialPublicKey to Buffer (length: ${credentialPublicKeyBuffer?.length})`);

        authenticatorDataForLib = {
            credentialID: credentialIDBuffer,
            publicKey: credentialPublicKeyBuffer, // Library expects 'publicKey'
            counter: storedCredential.counter,
            transports: storedCredential.transports,
        };
        console.log(`DEBUG: Prepared authenticator object for library:`, authenticatorDataForLib);
    } catch (e) {
        console.error("Error preparing authenticator object for verification:", e);
        return res.status(500).send({ error: 'Internal server error preparing authenticator data' });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: user.currentChallenge,
            expectedOrigin,
            expectedRPID: rpID,
            authenticator: authenticatorDataForLib, // Pass the dynamically prepared object
            requireUserVerification: false, // Set based on policy (usually true for login)
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