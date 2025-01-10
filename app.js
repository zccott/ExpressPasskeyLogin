require('dotenv').config();
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
  } = require("@simplewebauthn/server")
  const express = require("express")
  const cors = require("cors")
  const cookieParser = require("cookie-parser")
  const {
    getUserByEmail,
    createUser,
    updateUserCounter,
    getUserById,
  } = require("./mydb")
  
const { connectDB } = require("./mydb");
connectDB();

  const app = express()
  app.use(express.json())
  app.use(cookieParser())

  
  
//   const CLIENT_URL = "http://localhost:4200"
//   const RP_ID = "localhost"
    const CLIENT_URL = "https://angular-passkey-login.vercel.app"
    const RP_ID = "angular-passkey-login.vercel.app"

  app.use(cors({ origin: CLIENT_URL, credentials: true }))
  
  app.get("/init-register", async (req, res) => {
    console.log("init register")
    const email = req.query.email;
    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }

    try {
        const existingUser = await getUserByEmail(email); // Add `await` here
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }

        const options = await generateRegistrationOptions({
            rpID: RP_ID,
            rpName: "zccott",
            userName: email,
        });

        res.cookie(
            "regInfo",
            JSON.stringify({
                userId: options.user.id,
                email,
                challenge: options.challenge,
            }),
            { httpOnly: true, maxAge: 60000000, secure: true, sameSite: "none" }
        );

        res.json(options);
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

  
  app.post("/verify-register", async (req, res) => {
    const regInfo = JSON.parse(req.cookies.regInfo);
    console.log("/verify-register")
    console.log(req.body);
    console.log(req.cookies);
    if (!regInfo) {
      return res.status(400).json({ error: "Registration info not found" })
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: regInfo.challenge,
      expectedOrigin: CLIENT_URL,
      expectedRPID: RP_ID,
    })

  
    if (verification.verified) {
      createUser(regInfo.userId, regInfo.email, {
        id: verification.registrationInfo.credentialID,
        publicKey: Buffer.from(verification.registrationInfo.credentialPublicKey), // Convert to Buffer
        counter: verification.registrationInfo.counter,
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        transport: req.body.transports,
      })
      res.clearCookie("regInfo")
      return res.json({ verified: verification.verified })
    } else {
      return res
        .status(400)
        .json({ verified: false, error: "Verification failed" })
    }
  })
  
  app.get("/init-auth", async (req, res) => {
    const email = req.query.email
    if (!email) {
        return res.status(400).json({ error: "Email is required" })
    }

    try {
        const user = await getUserByEmail(email) // Add `await` here
        if (user == null) {
            return res.status(400).json({ error: "No user for this email" })
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
        })

        res.cookie(
            "authInfo",
            JSON.stringify({
                userId: user.id,
                challenge: options.challenge,
            }),
            { httpOnly: true, maxAge: 60000, secure: true, sameSite: "none" }
        )
        res.json(options)
    } catch (error) {
        res.status(500).json({ error: "Internal server error" })
    }
})

  
app.post("/verify-auth", async (req, res) => {
    const authInfo = JSON.parse(req.cookies.authInfo)
    console.log('authInfo', authInfo)
  
    if (!authInfo) {
        return res.status(400).json({ error: "Authentication info not found" })
    }

    try {
        // Add `await` here to ensure the user data is resolved
        const user = await getUserById(authInfo.userId)
        console.log('user', user)

        if (user == null || user.passKey.id != req.body.id) {
            return res.status(400).json({ error: "Invalid user" })
        }

        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: authInfo.challenge,
            expectedOrigin: CLIENT_URL,
            expectedRPID: RP_ID,
            authenticator: {
                credentialID: user.passKey.id,
                credentialPublicKey: user.passKey.publicKey,
                counter: user.passKey.counter,
                transports: user.passKey.transports,
            },
        })

        if (verification.verified) {
            updateUserCounter(user.id, verification.authenticationInfo.newCounter)
            res.clearCookie("authInfo")
            // Save user in a session cookie
            return res.json({ verified: verification.verified })
        } else {
            return res.status(400).json({ verified: false, error: "Verification failed" })
        }
    } catch (error) {
        console.error("Error during verify-auth:", error)
        res.status(500).json({ error: "Internal server error" })
    }
})

  
  app.listen(3000,"0.0.0.0", () => {
    console.log("Server is running on http://localhost:3000")
  })
  



  