const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const {
  getUserByEmail,
  createUser,
  updateUserCounter,
  getUserById,
} = require("./db");

const { connectDB } = require("./db");
connectDB();

const app = express();
app.use(express.json());
app.use(cookieParser());



app.use(cors({ origin: CLIENT_URL, credentials: true }));

app.get("/init-register", async (req, res) => {
  console.log("init register");
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await getUserByEmail(email);
  if (user != null) {
    return res.status(400).json({ error: "User already exists" });
  }

  const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: "Web Dev Simplified",
    userName: email,
  });

  res.cookie(
    "regInfo",
    JSON.stringify({
      userId: options.user.id,
      email,
      challenge: options.challenge,
    }),
    { httpOnly: true, maxAge: 60000, secure: true }
  );
  res.json(options);
});

app.post("/verify-register", async (req, res) => {
  console.log("verify register");
  const regInfo = JSON.parse(req.cookies.regInfo);

  if (!regInfo) {
    return res.status(400).json({ error: "Registration info not found" });
  }

  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge: regInfo.challenge,
    expectedOrigin: CLIENT_URL,
    expectedRPID: RP_ID,
  });

  if (verification.verified) {
    // Convert the public key to Base64 before storing it
    const publicKeyBase64 = verification.registrationInfo.credentialPublicKey.toString('base64');

    await createUser(regInfo.userId, regInfo.email, {
      id: verification.registrationInfo.credentialID,
      publicKey: publicKeyBase64,  // Store the Base64 encoded public key
      counter: verification.registrationInfo.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      transport: req.body.transports,
    });
    res.clearCookie("regInfo");
    return res.json({ verified: verification.verified });
  } else {
    return res.status(400).json({ verified: false, error: "Verification failed" });
  }
});

app.get("/init-auth", async (req, res) => {
  console.log("init auth");
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await getUserByEmail(email);
  if (user == null) {
    return res.status(400).json({ error: "No user for this email" });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [
      {
        id: user.passKey.id,
        type: "public-key",
        transports: user.passKey.transports,
      },
    ],
  });

  res.cookie(
    "authInfo",
    JSON.stringify({
      userId: user.id,
      challenge: options.challenge,
    }),
    { httpOnly: true, maxAge: 60000, secure: true }
  );
  res.json(options);
});

app.post("/verify-auth", async (req, res) => {
  console.log("verify auth");
  const authInfo = JSON.parse(req.cookies.authInfo);

  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = await getUserById(authInfo.userId);
  if (user == null || user.passKey.id != req.body.id) {
    return res.status(400).json({ error: "Invalid user" });
  }

  // Decode the Base64 public key from the database
  const publicKeyBuffer = Buffer.from(user.passKey.publicKey, "base64");

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: authInfo.challenge,
    expectedOrigin: CLIENT_URL,
    expectedRPID: RP_ID,
    authenticator: {
      credentialID: user.passKey.id,
      credentialPublicKey: publicKeyBuffer,  // Pass the decoded public key
      counter: user.passKey.counter,
      transports: user.passKey.transports,
    },
  });

  if (verification.verified) {
    await updateUserCounter(user.id, verification.authenticationInfo.newCounter);
    res.clearCookie("authInfo");
    return res.json({ verified: verification.verified });
  } else {
    return res.status(400).json({ verified: false, error: "Verification failed" });
  }
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});


