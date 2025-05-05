const express = require('express');
const cors = require('cors');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// Generate RSA key pair (once, for demo purpose)
const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair({ bits: 2048 });
const privatePem = forge.pki.privateKeyToPem(privateKey);
const publicPem = forge.pki.publicKeyToPem(publicKey);

// Send public key to frontend
app.get('/public-key', (req, res) => {
  res.send({ publicKey: publicPem });
});

// Receive encrypted form data, decrypt, verify, and respond
app.post('/login', (req, res) => {
  try {
    const encryptedData = req.body.encrypted;
    const decrypted = privateKey.decrypt(forge.util.decode64(encryptedData), 'RSA-OAEP');
    const credentials = JSON.parse(decrypted);

    // Example check (replace with real validation)
    if (credentials.username === 'admin' && credentials.password === 'password') {
      const token = jwt.sign({ username: 'admin' }, 'secret_key', { expiresIn: '1h' });
      return res.json({ success: true, token });
    } else {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, message: 'Decryption or validation failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
