import { Buffer } from 'buffer'; // Import Buffer
import express from 'express';
import cors from 'cors';
import crypto from 'crypto'; // Needed for challenges
import { Fido2Lib } from 'fido2-lib'; // Import fido2-lib

const app = express();
const PORT = 3001;

// --- Configuration ---
const rpID = 'localhost'; // Relying Party ID
// Origin MUST include the scheme and port
const expectedOrigin = `http://${rpID}:5173`; // Frontend origin
const rpName = 'FIDO2 Example'; // Relying Party Name

// --- Instantiate Fido2Lib ---
const f2l = new Fido2Lib({
    rpId: rpID,
    rpName: rpName,
    challengeSize: 128, // Bytes for challenge
    attestation: "direct", // Preference
    cryptoParams: [-7, -257], // Algorithms (ES256, RS256)
    authenticatorSelection: {
        requireResidentKey: true, // Require resident keys
        userVerification: "preferred", // "required", "preferred", or "discouraged"
    },
    timeout: 60000 // Timeout in milliseconds
});

// --- Middleware ---
app.use(cors({
    origin: expectedOrigin, // Allow requests only from the frontend origin
    credentials: true // Allow cookies/auth headers
}));
// Add middleware to parse JSON request bodies
// Increase limit to 5MB and add logging
app.use(express.json({ limit: '5mb' }));

// --- In-memory Storage ---
// !!! WARNING: USER STORE AND CREDENTIALS SHOULD BE IN A DATABASE IN PRODUCTION !!!
let userStore = {}; // Stores user info { email: { id, currentChallenge } }
let userCredentials = {}; // Stores credentials { userId: [ { credentialID (base64url), publicKey (PEM), counter, transports } ] }
let challenges = {}; // Store challenges { userId: challengeBuffer }

// Helper function to generate a unique user ID
const generateUserID = (email) => `user_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;

// Helper to safely get user credentials array
const getUserCredentials = (userId) => {
    if (!userCredentials[userId]) {
        userCredentials[userId] = [];
    }
    return userCredentials[userId];
};

// Helper to convert Base64URL to Buffer
const base64urlToBuffer = (base64urlString) => {
    // Pad with '=' characters if needed
    const padding = '='.repeat((4 - (base64urlString.length % 4)) % 4);
    const base64 = (base64urlString + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    return Buffer.from(base64, 'base64');
};

// Helper to convert Buffer to Base64URL
const bufferToBase64url = (buffer) => {
    // Ensure input is a Buffer
    const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
    // Use Node.js built-in base64url encoding
    return buf.toString('base64url');
};

// Helper function to convert Node Buffer to ArrayBuffer
function bufferToArrayBuffer(buf) {
    // Create an ArrayBuffer with the same byte length as the Buffer
    const ab = new ArrayBuffer(buf.length);
    // Create a Uint8Array view of the ArrayBuffer
    const view = new Uint8Array(ab);
    // Copy data from the Buffer into the Uint8Array view
    for (let i = 0; i < buf.length; ++i) {
        view[i] = buf[i];
    }
    return ab;
}

// --- Routes ---

app.get('/', (req, res) => {
    res.send('WebAuthn Example Server');
});

/**
 * Generates registration options using fido2-lib
 */
app.post('/generate-registration-options', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Missing email' });
    }

    let user = Object.values(userStore).find(u => u.email === email);
    if (!user) {
        const userId = generateUserID(email);
        user = { id: userId, email: email, name: email }; // Use email as name for simplicity
        userStore[userId] = user;
        console.log(`Created user: ${email} (ID: ${userId})`);
    } else {
        console.log(`User found: ${email} (ID: ${user.id})`);
    }

    try {
        const registrationOptions = await f2l.attestationOptions();

        // Apply the client's requested attestation conveyance preference (default to 'none')
        registrationOptions.attestation = "direct"; // Force "direct"

        // Add user information required by the spec
        registrationOptions.user = {
            id: user.id, // Use the generated or existing user ID
            name: user.name,
            displayName: user.name,
        };

        // Add excludeCredentials if user already has credentials
        const existingCredentials = getUserCredentials(user.id);
        if (existingCredentials.length > 0) {
             registrationOptions.excludeCredentials = existingCredentials.map(cred => ({
                id: cred.credentialID, // Keep as base64url for sending to client
                type: 'public-key',
                // transports: cred.transports, // Optional: specify transports if known
            }));
        }

        // Define acceptable credential algorithms - ONLY offer RS256 to try and force RSA attestation
        registrationOptions.pubKeyCredParams = [
            { type: "public-key", alg: -257 } // RS256 (RSA with SHA-256)
        ];

        // Set authenticator selection
        registrationOptions.authenticatorSelection = {
            requireResidentKey: true, // Require resident keys
            userVerification: "preferred", // "required", "preferred", or "discouraged"
        };

        // Store the original challenge Buffer
        challenges[user.id] = registrationOptions.challenge;
        console.log(`DEBUG: Stored challenge for ${user.id} (Buffer):`, challenges[user.id]);

        console.log(`Generated registration options for ${email}:`, JSON.stringify(registrationOptions, null, 2));

        // Encode challenge to base64url for sending to client
        const challengeBase64Url = Buffer.from(registrationOptions.challenge).toString('base64url');
        registrationOptions.challenge = challengeBase64Url;
        console.log(`DEBUG: Server sending challenge (base64url): ${challengeBase64Url}`);

        res.json(registrationOptions);

    } catch (e) {
        console.error('Error generating registration options:', e);
        res.status(500).json({ error: 'Failed to generate registration options', details: e.message });
    }
});

/**
 * Verifies the registration response using fido2-lib
 */
app.post('/verify-registration', async (req, res) => {
    // DEBUG: Log incoming request details *before* parsing body
    console.log('--- /verify-registration HIT ---');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Raw Body:', req.body); // Re-enable this log to see the full incoming body

    const { email, credential: clientAttestationResponse } = req.body;

    if (!email || !clientAttestationResponse || !clientAttestationResponse.id || !clientAttestationResponse.rawId || !clientAttestationResponse.response) {
        console.error("Missing email or required credential fields in request body:", req.body);
        return res.status(400).json({ error: 'Missing email or required credential fields' });
    }

    const user = Object.values(userStore).find(u => u.email === email);
    if (!user) {
        return res.status(400).json({ error: 'User not found' });
    }

    console.log(`Received registration verification request for ${email}:`, JSON.stringify(clientAttestationResponse, null, 2));

    // DEBUG: Log the raw ID string received before conversion
    console.log(`DEBUG: Raw clientAttestationResponse.id string: ${clientAttestationResponse.id}`);

    // Retrieve the original challenge Buffer
    const expectedChallenge = challenges[user.id];
    if (!expectedChallenge) {
        console.error(`Challenge not found for user ID: ${user.id}`);
        return res.status(400).json({ error: 'Challenge not found or expired.' });
    }
    console.log(`DEBUG: Retrieved challenge for ${user.id} (Buffer):`, expectedChallenge);

    try {
        // Construct the expected attestation object for fido2-lib
        // Note: rawId and parts of response are base64url encoded by the browser
        const attestationExpectations = {
            // Use the original challenge Buffer
            challenge: expectedChallenge,
            origin: expectedOrigin,
            rpId: rpID, // Must match the RP ID the authenticator used
            factor: "either", // Required by fido2-lib
            attestation: "direct" // Expect "direct" attestation now
        };

        console.log("DEBUG: Attestation Expectations:", {
            ...attestationExpectations,
            challenge: Buffer.from(attestationExpectations.challenge).toString('base64url'), // Log as string for readability
        });

        // fido2-lib expects the raw response object from the client
        // ** Modify the input to ensure ID is the decoded rawId **
        const verificationInput = {
            ...clientAttestationResponse,
            id: Buffer.from(clientAttestationResponse.rawId, 'base64url'), // Pass the decoded Buffer as 'id'
            rawId: Buffer.from(clientAttestationResponse.rawId, 'base64url') // Ensure rawId is also a Buffer if needed by lib
        };
        // Make sure response components are also buffers if needed (check lib requirements)
        verificationInput.response.clientDataJSON = Buffer.from(clientAttestationResponse.response.clientDataJSON, 'base64url');
        verificationInput.response.attestationObject = Buffer.from(clientAttestationResponse.response.attestationObject, 'base64url');

        console.log("DEBUG: Passing this object to attestationResult:", {
             ...verificationInput,
             id: `Buffer<${verificationInput.id.length}>`,
             rawId: `Buffer<${verificationInput.rawId.length}>`,
             response: {
                 ...verificationInput.response,
                 clientDataJSON: `Buffer<${verificationInput.response.clientDataJSON.length}>`,
                 attestationObject: `Buffer<${verificationInput.response.attestationObject.length}>`
             }
        });

        // Convert necessary fields from base64url string to ArrayBuffer
        const idArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAttestationResponse.rawId, 'base64url'));
        const rawIdArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAttestationResponse.rawId, 'base64url'));
        const clientDataJSONArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAttestationResponse.response.clientDataJSON, 'base64url'));
        const attestationObjectArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAttestationResponse.response.attestationObject, 'base64url'));

        const verificationInputArrayBuffer = {
            ...clientAttestationResponse,
            id: idArrayBuffer, // Use ArrayBuffer
            rawId: rawIdArrayBuffer // Use ArrayBuffer
        };
        // Make sure response components are also ArrayBuffers
        verificationInputArrayBuffer.response.clientDataJSON = clientDataJSONArrayBuffer; // Use ArrayBuffer
        verificationInputArrayBuffer.response.attestationObject = attestationObjectArrayBuffer; // Use ArrayBuffer

        console.log("DEBUG: Passing this object (with ArrayBuffers) to attestationResult:", {
             ...verificationInputArrayBuffer,
             id: `ArrayBuffer<${verificationInputArrayBuffer.id.byteLength}>`,
             rawId: `ArrayBuffer<${verificationInputArrayBuffer.rawId.byteLength}>`,
             response: {
                 ...verificationInputArrayBuffer.response,
                 clientDataJSON: `ArrayBuffer<${verificationInputArrayBuffer.response.clientDataJSON.byteLength}>`,
                 attestationObject: `ArrayBuffer<${verificationInputArrayBuffer.response.attestationObject.byteLength}>`
             }
        });

        const regResult = await f2l.attestationResult(
            verificationInputArrayBuffer, // Pass the modified object with ArrayBuffer ID
            attestationExpectations // The expectations for verification
        );

        console.log('Registration verification successful:', JSON.stringify(regResult, null, 2));

        // Clear the challenge
        delete challenges[user.id];
        console.log(`DEBUG: Deleted challenge for ${user.id}`);

        // Extract credential details from the result
        const authnrData = regResult.authnrData; // Parsed authenticator data
        const credentialIDString = clientAttestationResponse.id; // Use the base64url ID from the client response
        const publicKeyPEM = authnrData.get('credentialPublicKeyPem'); // Public key in PEM format
        const counter = authnrData.get('counter');
        const transports = clientAttestationResponse.response.transports || authnrData.get('transports') || []; // Get transports if available

        // Store the new credential
         const newCredential = {
            credentialID: credentialIDString, // Store as base64url string
            publicKey: publicKeyPEM, // Store as PEM string
            counter: counter,
            transports: transports
        };

        const userCreds = getUserCredentials(user.id);
        userCreds.push(newCredential);

        console.log(`Stored credential for ${email}: ID = ${credentialIDString.substring(0,20)}...`);

        res.json({ verified: true, userId: user.id });

    } catch (e) {
        console.error(`Error verifying registration for ${email}:`, e);
        // Clear challenge on error too
        if (challenges[user.id]) delete challenges[user.id];
        console.log(`DEBUG: Deleted challenge for ${user.id} after error`);
        res.status(400).json({ verified: false, error: 'Verification failed', details: e.message });
    }
}); // Correct closing syntax


/**
 * Generates authentication options using fido2-lib
 */
app.post('/generate-assertion-options', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Missing email' });
    }

    const user = Object.values(userStore).find(u => u.email === email);
    const userCreds = user ? getUserCredentials(user.id) : [];

    if (!user || userCreds.length === 0) {
        return res.status(404).json({ error: 'User not found or no credentials registered' });
    }

    try {
        const assertionOptions = await f2l.assertionOptions();

        // Store the original challenge Buffer
        challenges[user.id] = assertionOptions.challenge;
        console.log(`DEBUG: Stored challenge for ${user.id} (Buffer):`, challenges[user.id]);

        // Customize options
        assertionOptions.challenge = Buffer.from(assertionOptions.challenge).toString('base64url'); // Send base64url encoded
        assertionOptions.rpId = rpID; // Explicitly set rpId

        console.log(`Generated authentication options for ${email}:`, JSON.stringify(assertionOptions, null, 2));

        res.json(assertionOptions);

    } catch (e) {
        console.error('Error generating authentication options:', e);
        res.status(500).json({ error: 'Failed to generate authentication options', details: e.message });
    }
});

/**
 * Verifies the authentication response using fido2-lib
 */
app.post('/verify-assertion', async (req, res) => {
    const { email, credential: clientAssertionResponse } = req.body; // Renamed from credential to assertionResponse

    if (!email || !clientAssertionResponse || !clientAssertionResponse.id || !clientAssertionResponse.rawId || !clientAssertionResponse.response) {
        console.error('Missing email or assertion response data', { email, clientAssertionResponse });
        return res.status(400).json({ verified: false, message: 'Missing email or assertion response data' }); // Return JSON
    }

    const user = Object.values(userStore).find(u => u.email === email);
    const userCreds = user ? getUserCredentials(user.id) : [];

    if (!user || !challenges[user.id] || userCreds.length === 0) {
        return res.status(400).json({ error: 'User not found, authentication not initiated, or no credentials' });
    }

    console.log(`--- Verify Assertion Attempt for ${email} ---`);
    console.log("Received Assertion Object:", JSON.stringify(clientAssertionResponse, null, 2));

    // Find the specific credential used for this assertion
    const credentialIDFromResponse = clientAssertionResponse.id; // base64url
    const storedCredential = userCreds.find(cred => cred.credentialID === credentialIDFromResponse);

    if (!storedCredential) {
        console.error(`Error: Could not find credential with ID ${clientAssertionResponse.id} for user ${email}`);
        return res.status(404).json({ error: 'Credential not found for this user.' });
    }

    // Retrieve the original challenge
    const expectedChallenge = challenges[user.id]; // Use user.id to find challenge
    if (!expectedChallenge) {
        console.error(`Error: Challenge not found for user ID ${user.id}`);
        return res.status(400).json({ error: 'Challenge expired or invalid.' });
    }

    try {
        // --- Get the raw userHandle string received from the client ---
        const receivedUserHandleString = clientAssertionResponse.response.userHandle;
        if (!receivedUserHandleString) {
            // This might happen if not a resident key, but we required it.
            console.error("Error: userHandle missing in assertion response from client.");
            return res.status(400).json({ error: "User handle missing in assertion response." });
        }

        // Define expectations for the assertion
        const assertionExpectations = {
            challenge: expectedChallenge, // Original Buffer challenge
            origin: expectedOrigin,
            factor: 'either',
            rpId: rpID,
            publicKey: storedCredential.publicKey, // The stored PEM public key
            prevCounter: storedCredential.counter, // Expect counter from storage
            userHandle: bufferToArrayBuffer(Buffer.from(receivedUserHandleString, 'utf8')), // NEW: Use received userHandle string
        };

        // Convert necessary fields from base64url string to ArrayBuffer
        const idArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAssertionResponse.rawId, 'base64url'));
        const rawIdArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAssertionResponse.rawId, 'base64url'));
        const clientDataJSONArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAssertionResponse.response.clientDataJSON, 'base64url'));
        const authenticatorDataArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAssertionResponse.response.authenticatorData, 'base64url'));
        const signatureArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAssertionResponse.response.signature, 'base64url'));
        let userHandleArrayBuffer = undefined;
        if (clientAssertionResponse.response.userHandle) {
            // Convert the received user handle string to ArrayBuffer for the input object
            userHandleArrayBuffer = bufferToArrayBuffer(Buffer.from(clientAssertionResponse.response.userHandle, 'utf8'));
        }

        const assertionVerificationInput = {
            ...clientAssertionResponse,
            id: idArrayBuffer, // Use ArrayBuffer
            rawId: rawIdArrayBuffer // Use ArrayBuffer
        };
        // Ensure response components are ArrayBuffers
        assertionVerificationInput.response.clientDataJSON = clientDataJSONArrayBuffer; // Use ArrayBuffer
        assertionVerificationInput.response.authenticatorData = authenticatorDataArrayBuffer; // Use ArrayBuffer
        assertionVerificationInput.response.signature = signatureArrayBuffer; // Use ArrayBuffer
        // Use the converted received userHandle ArrayBuffer
        if (userHandleArrayBuffer) {
            assertionVerificationInput.response.userHandle = userHandleArrayBuffer; // Use ArrayBuffer
        }

        const verificationResult = await f2l.assertionResult(
            assertionVerificationInput, // Pass the modified object with ArrayBuffers
            assertionExpectations
        );

        // --- IMPORTANT: Update Counter ---
        const newCounter = verificationResult.authnrData.get("counter");
        storedCredential.counter = newCounter; // Update counter in our store

        // Clear the used challenge
        delete challenges[user.id];

        console.log('Authentication verification successful:', JSON.stringify(verificationResult, null, 2));

        res.json({ verified: true, userId: user.id });

    } catch (e) {
        console.error(`Error verifying authentication for ${email}:`, e);
        // Clear challenge on error too
        if (challenges[user.id]) delete challenges[user.id];
        res.status(400).json({ verified: false, error: 'Authentication verification failed', details: e.message });
    }
}); // Correct closing syntax


// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Backend server listening on port ${PORT}`);
    console.log(`Configuration: rpID='${rpID}', expectedOrigin='${expectedOrigin}'`);
});