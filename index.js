const fs = require('fs');
const crypto = require('crypto');

const ENCRYPTION_ALGORITHM = 'aes-256-ctr';

const IV_LENGTH_BYTES = 16;
const HASH_LENGTH_BYTES = 32;
const SALT_LENGTH_BYTES = 16;

const OPERATION_MODE_ENCRYPT = 'encrypt';
const OPERATION_MODE_DECRYPT = 'decrypt';

function main() {
    try {
        const args = parseAndValidateArguments();

        if (args.mode === OPERATION_MODE_ENCRYPT) {
            executeEncryptionWorkflow(args.filePath, args.primaryPassword, args.secondaryPassword);
        } else if (args.mode === OPERATION_MODE_DECRYPT) {
            executeDecryptionWorkflow(args.filePath, args.primaryPassword, args.secondaryPassword);
        }

    } catch (error) {
        console.error(`❌ ERROR: ${error.message}`);
        process.exit(1);
    }
}

function executeEncryptionWorkflow(filePath, encryptionPassword, validationPassword) {
    console.log(`🚀 Starting encryption workflow for file: ${filePath}`);

    const fileSalt = crypto.randomBytes(SALT_LENGTH_BYTES);

    const originalContent = readFileBytes(filePath);

    const securePayload = constructPayloadWithInternalCheck(originalContent, validationPassword, fileSalt);

    const { iv, encryptedData } = encryptBuffer(securePayload, encryptionPassword, fileSalt);

    const finalBuffer = Buffer.concat([fileSalt, iv, encryptedData]);

    const outputFilePath = `${filePath}.dpas`;
    fs.writeFileSync(outputFilePath, finalBuffer);

    console.log(`✅ SUCCESS: File encrypted successfully.`);
    console.log(`📁 Output: ${outputFilePath}`);
}

function executeDecryptionWorkflow(filePath, decryptionPassword, validationPassword) {
    console.log(`🔓 Starting decryption workflow for file: ${filePath}`);

    const fileData = readFileBytes(filePath);

    if (fileData.length < SALT_LENGTH_BYTES + IV_LENGTH_BYTES) {
        throw new Error("File is too short (corrupted).");
    }

    const fileSalt = fileData.subarray(0, SALT_LENGTH_BYTES);
    const restOfFile = fileData.subarray(SALT_LENGTH_BYTES);

    const { iv, encryptedContent } = parseEncryptedFile(restOfFile);

    const decryptedPayload = decryptBuffer(encryptedContent, decryptionPassword, iv, fileSalt);

    const extractedContent = validateAndExtractContent(decryptedPayload, validationPassword, fileSalt);

    const outputFilePath = filePath.replace('.dpas', '.decrypted');
    fs.writeFileSync(outputFilePath, extractedContent);

    console.log(`✅ SUCCESS: File decrypted and verified.`);
    console.log(`📁 Output: ${outputFilePath}`);
}

function constructPayloadWithInternalCheck(contentBuffer, internalPassword, salt) {
    const checkSalt = Buffer.concat([salt, Buffer.from('_INTERNAL_CHECK')]);

    const passwordHash = crypto.scryptSync(internalPassword, checkSalt, 32);

    const { iv, encryptedData } = encryptBuffer(contentBuffer, internalPassword, salt);

    return Buffer.concat([passwordHash, iv, encryptedData]);
}

function encryptBuffer(bufferToEncrypt, password, salt) {
    const key = deriveKeyFromPassword(password, salt);
    const iv = crypto.randomBytes(IV_LENGTH_BYTES);

    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(bufferToEncrypt), cipher.final()]);

    return { iv, encryptedData: encrypted };
}

function decryptBuffer(encryptedBuffer, password, iv, salt) {
    const key = deriveKeyFromPassword(password, salt);
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);

    return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

function validateAndExtractContent(decryptedPayload, expectedInternalPassword, salt) {
    const checkSalt = Buffer.concat([salt, Buffer.from('_INTERNAL_CHECK')]);
    const expectedHash = crypto.scryptSync(expectedInternalPassword, checkSalt, 32);

    if (decryptedPayload.length < HASH_LENGTH_BYTES) {
        throw new Error("Decrypted payload is too short. Invalid structure.");
    }

    const foundHash = decryptedPayload.subarray(0, HASH_LENGTH_BYTES);

    if (foundHash.equals(expectedHash)) {
        const restOfPayload = decryptedPayload.subarray(HASH_LENGTH_BYTES);

        const { iv, encryptedContent } = parseEncryptedFile(restOfPayload);

        const decryptedContent = decryptBuffer(encryptedContent, expectedInternalPassword, iv, salt);
        return decryptedContent;
    } else {
        throw new Error("Security Check Failed: Internal password hash mismatch (or wrong primary password).");
    }
}

function deriveKeyFromPassword(password, salt) {
    return crypto.scryptSync(password, salt, 32);
}

function parseEncryptedFile(fileData) {
    if (fileData.length < IV_LENGTH_BYTES) {
        throw new Error("File content too short for IV extraction.");
    }
    const iv = fileData.subarray(0, IV_LENGTH_BYTES);
    const encryptedContent = fileData.subarray(IV_LENGTH_BYTES);
    return { iv, encryptedContent };
}

function readFileBytes(filePath) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }
    return fs.readFileSync(filePath);
}

function parseAndValidateArguments() {
    const args = process.argv.slice(2);

    if (args.length < 4) {
        throw new Error(
            `Insufficient arguments.\nUsage: node DpasSecureManager.js <encrypt|decrypt> <file> <pass1> <pass2>`
        );
    }

    return {
        mode: args[0],
        filePath: args[1],
        primaryPassword: args[2],
        secondaryPassword: args[3]
    };
}

main();