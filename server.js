const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
require("dotenv").config();
const sendEmail = require("./emailService");
const { processSTKPush } = require("./mpesa"); // Import STK Push function
const crypto = require("crypto");
const DAILY_RATE = 0.0002739726;
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: "https://ifundapp.netlify.app",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
    allowedHeaders: "Content-Type, Authorization",
  })
);

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
});

function generateUserId() {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let userId = "";
  for (let i = 0; i < 6; i++) {
    userId += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return userId;
}

app.post("/api/register/step1", async (req, res) => {
  const { full_name, email, phone, password, ref } = req.body;

  if (!full_name || !email || !phone || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields." });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    let userId;
    let userIdExists = true;
    while (userIdExists) {
      userId = generateUserId();
      const result = await pool.query(
        "SELECT id FROM users WHERE user_id = $1",
        [userId]
      );
      userIdExists = result.rows.length > 0;
    }

    let result;
    try {
      result = await pool.query(
        "INSERT INTO users (user_id, full_name, email, phone, password_hash, registration_status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id",
        [userId, full_name, email, phone, hashedPassword, "step_1"]
      );
    } catch (dbError) {
      if (dbError.code === "23505") {
        return res
          .status(409)
          .json({ message: "Email or phone number already in use." });
      }
      console.error("Database Insertion Error:", dbError);
      return res
        .status(500)
        .json({ message: "Database error while creating user." });
    }

    const newUserId = result.rows[0].user_id;

    if (ref) {
      try {
        const referrerResult = await pool.query(
          "SELECT user_id FROM users WHERE user_id = $1",
          [ref]
        );
        if (referrerResult.rowCount > 0) {
          const referrerId = referrerResult.rows[0].user_id;

          await pool.query(
            "INSERT INTO referrals (referrer_user_id, referred_user_id) VALUES ($1, $2)",
            [referrerId, newUserId]
          );
        } else {
          console.warn("Invalid referral code:", ref);
        }
      } catch (referralError) {
        console.error("Referral Processing Error:", referralError);
        return res
          .status(500)
          .json({ message: "Error processing referral information." });
      }
    }

    res.status(201).json({
      message: "Step 1 completed. Proceed to step 2.",
      userId: newUserId,
    });
  } catch (error) {
    console.error("Step 1 Error:", error);

    if (error.code === "ECONNREFUSED") {
      return res.status(503).json({ message: "Database connection refused." });
    }

    res.status(500).json({ message: "Server error while creating user." });
  }
});

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "ifundmedia",
    format: async (req, file) => path.extname(file.originalname).substring(1),
    public_id: (req, file) => `${file.fieldname}-${Date.now()}`,
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed."));
    }
  },
});

app.post(
  "/api/register/step2",
  upload.fields([{ name: "front_id" }, { name: "back_id" }]),
  async (req, res) => {
    const { userId } = req.body;
    const frontIdUrl = req.files["front_id"]?.[0]?.path;
    const backIdUrl = req.files["back_id"]?.[0]?.path;

    if (!userId || !frontIdUrl || !backIdUrl) {
      return res
        .status(400)
        .json({ message: "Please provide userId and both ID images." });
    }

    try {
      await pool.query(
        "INSERT INTO user_ids (user_id, front_id_path, back_id_path) VALUES ($1, $2, $3)",
        [userId, frontIdUrl, backIdUrl]
      );

      await pool.query(
        "UPDATE users SET registration_status = $1 WHERE user_id = $2",
        ["step_2", userId]
      );

      res.status(201).json({
        message: "Step 2 completed. Proceed to step 3.",
        filesUploaded: {
          front_id: frontIdUrl,
          back_id: backIdUrl,
        },
      });
    } catch (error) {
      console.error(
        "Database Error during Step 2:",
        error.message,
        error.stack
      );
      res
        .status(500)
        .json({ message: "Server error while uploading ID images." });
    }
  }
);

app.post("/api/register/step3", async (req, res) => {
  const { userId, termsAccepted, privacyPolicyAccepted } = req.body;

  if (
    typeof termsAccepted !== "boolean" ||
    typeof privacyPolicyAccepted !== "boolean" ||
    !userId
  ) {
    return res.status(400).json({
      message:
        "Please provide valid values for userId, termsAccepted, and privacyPolicyAccepted.",
    });
  }

  try {
    const userResult = await pool.query(
      "SELECT email FROM users WHERE user_id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const userEmail = userResult.rows[0].email;
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    await pool.query(
      `INSERT INTO user_verifications (user_id, code, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET code = $2, updated_at = NOW()`,
      [userId, verificationCode]
    );

    const existingConsent = await pool.query(
      "SELECT * FROM user_consents WHERE user_id = $1",
      [userId]
    );

    if (existingConsent.rows.length > 0) {
      await pool.query(
        "UPDATE user_consents SET terms_accepted = $1, privacy_policy_accepted = $2, updated_at = CURRENT_TIMESTAMP WHERE user_id = $3",
        [termsAccepted, privacyPolicyAccepted, userId]
      );
    } else {
      await pool.query(
        "INSERT INTO user_consents (user_id, terms_accepted, privacy_policy_accepted) VALUES ($1, $2, $3)",
        [userId, termsAccepted, privacyPolicyAccepted]
      );
    }

    await pool.query(
      "UPDATE users SET registration_status = $1 WHERE user_id = $2",
      ["step_3", userId]
    );

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          userEmail,
          "Email Verification",
          `Your verification code is: ${verificationCode}`,
          `<p>Your verification code is: <strong>${verificationCode}</strong></p>`
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    res.status(200).json({
      message:
        "Step 3 completed. Verification email is being sent asynchronously.",
    });
  } catch (error) {
    console.error("Step 3 Error:", error);
    res.status(500).json({ message: "Server error while processing step 3." });
  }
});

app.post("/api/register/step4", async (req, res) => {
  const { userId, verificationCode } = req.body;

  if (!userId || !verificationCode) {
    return res
      .status(400)
      .json({ message: "Please provide userId and verification code." });
  }

  try {
    const codeResult = await pool.query(
      "SELECT * FROM user_verifications WHERE user_id = $1",
      [userId]
    );

    if (codeResult.rows.length === 0) {
      return res.status(400).json({
        message: "No verification code found. Please request a new code.",
      });
    }

    const validCode = codeResult.rows[0].code;

    if (verificationCode !== validCode) {
      return res.status(400).json({ message: "Invalid verification code." });
    }

    await pool.query(
      "UPDATE users SET registration_status = $1 WHERE user_id = $2",
      ["complete", userId]
    );

    const userResult = await pool.query(
      "SELECT email FROM users WHERE user_id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const email = userResult.rows[0].email;

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          email,
          "Welcome to iFund – Your Financial Journey Begins!",
          `Dear Valued Member,
        
          Congratulations! Your registration with iFund is now complete. We're thrilled to have you on board as part of our growing community.
        
          iFund empowers you to take control of your savings and financial goals effortlessly. Get started today by exploring our platform.
        
          If you have any questions, feel free to reach out to our support team.
        
          Best regards,  
          The iFund Team`,
          `<h1 style="color: #1FC17B;">Welcome to iFund – Your Financial Journey Begins!</h1>
           <p>Dear Valued Member,</p>
           <p>Congratulations! Your registration with <strong>iFund</strong> is now complete. We're thrilled to have you on board as part of our growing community.</p>
           <p>iFund empowers you to take control of your savings and financial goals effortlessly. <a href="https://your-ifund-platform.com/login" style="color: #1FC17B; font-weight: bold;">Log in</a> and get started today!</p>
           <p>If you have any questions, feel free to reach out to our <a href="mailto:support@ifund.com" style="color: #1FC17B;">support team</a>.</p>
           <br>
           <p>Best regards,</p>
           <p><strong>The iFund Team</strong></p>`
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    const accountResult = await pool.query(
      "SELECT * FROM accounts WHERE user_id = $1",
      [userId]
    );

    if (accountResult.rows.length === 0) {
      await pool.query(
        "INSERT INTO accounts (user_id, balance) VALUES ($1, $2)",
        [userId, 0]
      );
    }

    await pool.query(`INSERT INTO interests (user_id) VALUES ($1)`, [userId]);

    res.status(200).json({ message: "Registration completed successfully!" });
  } catch (error) {
    console.error("Step 4 Error:", error);
    res.status(500).json({ message: "Server error while verifying user." });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "Please provide both email and password." });
  }

  const superadminEmail = process.env.ADMIN_EMAIL_ADDRESS;
  const superadminPassword = process.env.ADMIN_PASSWORD;

  try {
    if (email === superadminEmail && password === superadminPassword) {
      const token = jwt.sign(
        { userId: "superadmin", role: "superadmin" },
        process.env.JWT_SECRET_KEY,
        { expiresIn: "1h" }
      );

      return res.status(200).json({
        message: "Login successful",
        token,
        user: {
          id: "superadmin",
          name: "Super Admin",
          role: "superadmin",
        },
      });
    }
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const user = userResult.rows[0];

    if (user.delete_request_date !== null) {
      return res.status(401).json({
        message:
          "Account deletion request is in process. Please contact support.",
      });
    }
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials." });
    }
    const { registration_status } = user;

    if (registration_status && registration_status !== "complete") {
      const nextStep = getNextStep(registration_status);
      const formattedNextStep = nextStep.replace("_", "-");

      return res.status(200).json({
        message: "Registration incomplete. Please complete your registration.",
        registrationIncomplete: true,
        nextStep: formattedNextStep,
        userId: user.user_id,
      });
    }

    const accountResult = await pool.query(
      "SELECT two_step_verification FROM accounts WHERE user_id = $1",
      [user.user_id]
    );

    if (accountResult.rows.length === 0) {
      return res.status(401).json({
        message: "Account information not found. Please contact support.",
      });
    }

    const twoStepEnabled = accountResult.rows[0].two_step_verification;

    if (twoStepEnabled) {
      const verificationCode = Math.floor(
        100000 + Math.random() * 900000
      ).toString();

      await pool.query(
        `INSERT INTO user_verifications (user_id, code, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET code = $2, updated_at = NOW()`,
        [user.user_id, verificationCode]
      );

      // Send email asynchronously
      (async () => {
        try {
          await sendEmail(
            email,
            "2FA Verification Code",
            `Your verification code is: ${verificationCode}`,
            `<p>Your verification code is: <strong>${verificationCode}</strong></p>`
          );
        } catch (error) {
          console.error("Failed to send email:", error);
        }
      })();

      return res.status(200).json({
        message: "Two-step verification code sent. Please verify to proceed.",
        verificationRequired: true,
        userId: user.user_id,
      });
    }

    const token = jwt.sign(
      { userId: user.user_id, role: "user" },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.user_id,
        name: user.full_name,
        role: "user",
      },
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error." });
  }
});

function getNextStep(registrationStatus) {
  const steps = ["step_1", "step_2", "step_3", "step_4"];
  const currentStepIndex = steps.indexOf(registrationStatus);
  return currentStepIndex >= 0 && currentStepIndex < steps.length - 1
    ? steps[currentStepIndex + 1]
    : "complete";
}

app.post("/api/login/verify-code", async (req, res) => {
  const { userId, verificationCode } = req.body;

  if (!userId || !verificationCode) {
    return res
      .status(400)
      .json({ message: "User ID and verification code are required." });
  }

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [userId]
    );

    const user = userResult.rows[0];

    const result = await pool.query(
      "SELECT * FROM user_verifications WHERE user_id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        message: "No verification code found. Please request a new code.",
      });
    }

    const validCode = result.rows[0].code;

    if (verificationCode !== validCode) {
      return res.status(400).json({ message: "Invalid verification code." });
    }

    const token = jwt.sign(
      { userId, role: "user" },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Verification successful!",
      token,
      user: {
        id: user.user_id,
        name: user.full_name,
        role: "user",
      },
    });
  } catch (error) {
    console.error("Error verifying code:", error);
    res.status(500).json({ message: "Server error during verification." });
  }
});

app.post("/api/login/resend-code", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "User ID is required." });
  }

  try {
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    await pool.query(
      `INSERT INTO user_verifications (user_id, code, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET code = $2, updated_at = NOW()`,
      [userId, verificationCode]
    );

    const userResult = await pool.query(
      "SELECT email FROM users WHERE user_id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const email = userResult.rows[0].email;

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          email,
          "Verification Code",
          `Your verification code is: ${verificationCode}`,
          `<p>Your verification code is: <strong>${verificationCode}</strong></p>`
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    res.status(200).json({ message: "A new verification code has been sent." });
  } catch (error) {
    console.error("Error resending verification code:", error);
    res.status(500).json({ message: "Server error during code resend." });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const userRes = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);
    if (userRes.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    const token = crypto.randomBytes(32).toString("hex");
    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expiry = NOW() + INTERVAL '1 hour' WHERE email = $2",
      [token, email]
    );

    const resetLink = `http://localhost:5173/reset-password/${token}`;

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          email,
          "Password Reset Request",
          `Click the link to reset your password: ${resetLink}`
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    res.json({ message: "Password reset link sent" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const userRes = await pool.query(
      "SELECT id,email FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()",
      [token]
    );
    if (userRes.rows.length === 0)
      return res.status(400).json({ message: "Invalid or expired token" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = $2",
      [hashedPassword, token]
    );

    const email = userRes.rows[0].email;

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          email,
          "Password Reset",
          `Your password was reset successfully!`,
          "<h5>Your password was reset successfully!</h5>"
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    res.json({ message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/deposits", async (req, res) => {
  const { userId, amount, mpesaNumber, description } = req.body;

  if (!userId || !amount || !mpesaNumber) {
    return res.status(400).json({ message: "All fields are required." });
  }

  if (!/^\d{12}$/.test(mpesaNumber)) {
    return res
      .status(400)
      .json({ message: "Invalid M-Pesa number. It must be 12 digits." });
  }

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const depositResult = await pool.query(
      "SELECT * FROM deposits WHERE user_id = $1",
      [userId]
    );
    const isFirstDeposit = depositResult.rows.length === 0;
    if (isFirstDeposit && amount < 500) {
      return res
        .status(400)
        .json({ message: "Initial deposit must be at least 500." });
    }

    if (isFirstDeposit) {
      await pool.query(
        "UPDATE users SET account_status = $1 WHERE user_id = $2",
        ["active", userId]
      );
    }

    await pool.query(
      "INSERT INTO deposits (user_id, amount, mpesa_number, description) VALUES ($1, $2, $3, $4)",
      [userId, amount, mpesaNumber, description || null]
    );

    const accountUpdateResult = await pool.query(
      "UPDATE accounts SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2 RETURNING balance",
      [amount, userId]
    );

    if (accountUpdateResult.rowCount === 0) {
      return res.status(500).json({
        message: "Failed to update account balance. Account may not exist.",
      });
    }

    await pool.query(
      "INSERT INTO transactions (user_id, type, amount, description) VALUES ($1, $2, $3, $4)",
      [userId, "deposit", amount, description || null]
    );

    // Call M-Pesa STK Push function
    await processSTKPush(mpesaNumber, amount);

    const userEmail = userResult.rows[0].email;

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          userEmail,
          "Deposit Confirmation",
          `Your deposit of ${amount} was successful`,
          `<p>Your deposit of <strong>${amount}</strong> was successful</p>`
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    res.status(201).json({
      message: "Deposit successful. M-Pesa STK Push initiated.",
      newBalance: parseFloat(accountUpdateResult.rows[0].balance),
    });
  } catch (error) {
    console.error("Deposit Error:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.post("/api/goals", upload.single("image"), async (req, res) => {
  const { user_id, title, target_amount, description, end_date, deposit } =
    req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;
  if (
    !user_id ||
    !title ||
    !target_amount ||
    !end_date ||
    !description ||
    deposit === undefined
  ) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const goalQuery = `
        INSERT INTO goals (user_id, title, target_amount, description, image_path, end_date, saved_amount)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING goal_id;
      `;
      const goalResult = await client.query(goalQuery, [
        user_id,
        title,
        target_amount,
        description,
        image,
        end_date,
        deposit,
      ]);

      const goalId = goalResult.rows[0].goal_id;
      const memberQuery = `
        INSERT INTO communities_members (goal_id, user_id, saved_amount, goal_role)
        VALUES ($1, $2, $3, $4);
      `;
      await client.query(memberQuery, [goalId, user_id, deposit, "admin"]);
      const updateBalanceQuery = `
        UPDATE accounts
        SET balance = balance - $1, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = $2;
      `;
      await client.query(updateBalanceQuery, [deposit, user_id]);

      const updateAllocatedFundsQuery = `
      UPDATE accounts
      SET allocated_funds = allocated_funds + $1, updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $2;
    `;
      await client.query(updateAllocatedFundsQuery, [deposit, user_id]);

      await client.query("COMMIT");

      const userResult = await pool.query(
        "SELECT email FROM users WHERE user_id = $1",
        [user_id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: "User not found." });
      }

      const email = userResult.rows[0].email;

      // Send email asynchronously
      (async () => {
        try {
          await sendEmail(
            email,
            "Saving Goal Creation",
            `Your saving goal for ${title} was created successfully`,
            `<p>Your saving goal for <strong>${title}</strong> was created successfully</p>`
          );
        } catch (error) {
          console.error("Failed to send email:", error);
        }
      })();

      res.status(201).json({
        message: "Goal created successfully.",
        goalId: goalId,
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Error creating goal:", error);
      res
        .status(500)
        .json({ error: error.message || "Internal server error." });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ error: "Database connection error." });
  }
});

app.post("/api/withdrawals", async (req, res) => {
  const { userId, amount, mpesaNumber, description } = req.body;

  if (!userId || !amount || !mpesaNumber) {
    return res
      .status(400)
      .json({ message: "User ID, amount, and mpesa number are required." });
  }

  if (amount <= 0) {
    return res
      .status(400)
      .json({ message: "Amount must be greater than zero." });
  }

  try {
    const accountResult = await pool.query(
      "SELECT * FROM accounts WHERE user_id = $1",
      [userId]
    );

    if (accountResult.rows.length === 0) {
      return res.status(404).json({ message: "Account not found." });
    }
    const depositResult = await pool.query(
      "SELECT * FROM deposits WHERE user_id = $1 AND mpesa_number = $2",
      [userId, mpesaNumber]
    );

    if (depositResult.rows.length === 0) {
      return res.status(404).json({
        message: "No matching mpesa number found in deposits for this user.",
      });
    }

    const account = accountResult.rows[0];
    if (account.balance < amount) {
      return res
        .status(400)
        .json({ message: "Insufficient balance for withdrawal." });
    }

    await pool.query(
      "INSERT INTO withdrawals (user_id, amount, description) VALUES ($1, $2, $3)",
      [userId, amount, description || null]
    );

    await pool.query(
      "UPDATE accounts SET balance = balance - $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2",
      [amount, userId]
    );

    await pool.query(
      "UPDATE accounts SET balance = balance - $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2",
      [amount, userId]
    );
    await pool.query(
      "INSERT INTO transactions (user_id, type, amount, description) VALUES ($1, $2, $3, $4)",
      [userId, "withdrawal", amount, description || null]
    );

    const userResult = await pool.query(
      "SELECT email FROM users WHERE user_id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const userEmail = userResult.rows[0].email;

    // Send email asynchronously
    (async () => {
      try {
        await sendEmail(
          userEmail,
          "Withdrawals Cofirmation",
          `Your withdrawal of ${amount} was successful`,
          `<p>Your withdrawal of <strong>${amount}</strong> was successful</p>`
        );
      } catch (error) {
        console.error("Failed to send email:", error);
      }
    })();

    res.status(201).json({ message: "Withdrawal successful." });
  } catch (error) {
    console.error("Withdrawal Error:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/api/accounts/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const accountResult = await pool.query(
      "SELECT balance FROM accounts WHERE user_id = $1",
      [userId]
    );
    const allocatedResult = await pool.query(
      "SELECT allocated_funds FROM accounts WHERE user_id = $1",
      [userId]
    );
    if (accountResult.rows.length === 0) {
      return res.status(404).json({ message: "Account not found." });
    }

    const account = accountResult.rows[0];
    const allocated = allocatedResult.rows[0];

    const userResult = await pool.query(
      "SELECT account_status FROM users WHERE user_id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const user = userResult.rows[0];

    res.status(200).json({
      account: {
        balance: account.balance,
        accountStatus: user.account_status,
        allocated: allocated.allocated_funds,
      },
    });
  } catch (error) {
    console.error("Error fetching account details:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/api/profiles/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const userResult = await pool.query(
      "SELECT full_name AS name, email, phone, profile_picture FROM users WHERE user_id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const user = userResult.rows[0];

    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/api/transactions/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const transactionsResult = await pool.query(
      "SELECT type, amount, created_at FROM transactions WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    );

    if (transactionsResult.rows.length === 0) {
      return res.json({ message: "No transactions found for this user." });
    }

    const transactions = transactionsResult.rows.map((transaction) => ({
      type: transaction.type,
      amount: parseFloat(transaction.amount),
      date: transaction.created_at.toISOString(),
    }));

    res.status(200).json({ transactions });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/api/goals/:userId", async (req, res) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");
      const fundsQuery = `
        SELECT allocated_funds 
        FROM accounts
        WHERE user_id = $1;
      `;
      const fundsResult = await client.query(fundsQuery, [userId]);

      if (
        fundsResult.rows.length === 0 ||
        fundsResult.rows[0].allocated_funds === null
      ) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "User account not found." });
      }
      const allocatedFunds = fundsResult.rows[0].allocated_funds;
      const goalsQuery = `
        SELECT 
          g.goal_id,
          g.title,
          g.description,
          g.target_amount,
          g.saved_amount,
          g.image_path,
          g.start_date,
          g.end_date,
          g.created_at,
          g.updated_at
        FROM goals g
        LEFT JOIN communities_members cm 
          ON cm.goal_id = g.goal_id AND cm.user_id = $1
        WHERE g.user_id = $1 OR cm.user_id = $1
        ORDER BY g.created_at DESC;
      `;
      const goalsResult = await client.query(goalsQuery, [userId]);

      const baseUrl = "http://localhost:5000";

      const goals = goalsResult.rows.map((goal) => ({
        ...goal,
        image_url: goal.image_path ? `${baseUrl}${goal.image_path}` : null,
      }));

      await client.query("COMMIT");

      res.status(200).json({ allocatedFunds, goals });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Error fetching user data:", error);
      res.status(500).json({ error: "Internal server error." });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Database connection error:", error);
    res.status(500).json({ error: "Database connection error." });
  }
});

app.get("/api/goal/:goalId", async (req, res) => {
  const { goalId } = req.params;
  const { userId } = req.query;

  if (!goalId) {
    return res.status(400).json({ error: "Goal ID is required." });
  }

  if (!userId) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const goalQuery = `
        SELECT 
          goal_id, 
          title, 
          description, 
          target_amount, 
          saved_amount, 
          image_path, 
          start_date, 
          end_date, 
          created_at, 
          updated_at
        FROM goals 
        WHERE goal_id = $1;
      `;
      const goalResult = await client.query(goalQuery, [goalId]);

      if (goalResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Goal not found." });
      }

      const goal = goalResult.rows[0];

      if (goal.image_path) {
        const baseUrl = "http://localhost:5000";
        goal.image_url = `${baseUrl}${goal.image_path}`;
        delete goal.image_path;
      }

      const membersQuery = `
      SELECT 
        cm.user_id, 
        u.full_name, 
        u.profile_picture,
        cm.contribution, 
        cm.joined_at, 
        cm.goal_role
      FROM communities_members cm
      JOIN users u ON cm.user_id = u.user_id
      WHERE cm.goal_id = $1;
    `;

      const membersResult = await client.query(membersQuery, [goalId]);

      const members = membersResult.rows;

      const currentUserRole =
        members.find((member) => member.user_id === userId)?.goal_role ||
        "member";

      const memberCount = members.length;

      await client.query("COMMIT");

      res.status(200).json({
        goal: {
          ...goal,
          members,
          memberCount,
          goalRole: currentUserRole,
        },
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Error fetching goal data:", error);
      res.status(500).json({ error: "Internal server error." });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Database connection error:", error);
    res.status(500).json({ error: "Database connection error." });
  }
});

app.put("/api/goals/:goalId", upload.single("image"), async (req, res) => {
  const { goalId } = req.params;
  const { title, target_amount, description, end_date } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!title || !target_amount || !end_date || !description) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const goalQuery = `
        UPDATE goals
        SET title = $1, target_amount = $2, description = $3, image_path = COALESCE($4, image_path), end_date = $5
        WHERE goal_id = $6
        RETURNING goal_id;
      `;
      const goalResult = await client.query(goalQuery, [
        title,
        target_amount,
        description,
        image,
        end_date,
        goalId,
      ]);

      await client.query("COMMIT");

      res.status(200).json({
        message: "Goal updated successfully.",
        goalId: goalResult.rows[0].goal_id,
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Error updating goal:", error);
      res
        .status(500)
        .json({ error: error.message || "Internal server error." });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ error: "Database connection error." });
  }
});

app.post("/api/goals/:goalId/contribute", async (req, res) => {
  const { goalId } = req.params;
  const { userId, contributionAmount } = req.body;

  if (!userId || !contributionAmount || contributionAmount <= 0) {
    return res.status(400).json({ error: "Invalid input data." });
  }

  try {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const goalQuery = `
        SELECT title, saved_amount, target_amount, user_id AS admin_id 
        FROM goals 
        WHERE goal_id = $1;
      `;
      const goalResult = await client.query(goalQuery, [goalId]);

      if (goalResult.rows.length === 0) {
        throw new Error("Goal not found.");
      }

      const { title, saved_amount, target_amount, admin_id } =
        goalResult.rows[0];

      const savedAmount = parseFloat(saved_amount);
      const targetAmount = parseFloat(target_amount);
      const contribution = parseFloat(contributionAmount);

      const newSavedAmount = savedAmount + contribution;
      if (newSavedAmount > targetAmount) {
        throw new Error("Contribution exceeds target amount.");
      }

      const updateGoalQuery = `
        UPDATE goals 
        SET saved_amount = saved_amount + $1 
        WHERE goal_id = $2;
      `;
      await client.query(updateGoalQuery, [contributionAmount, goalId]);

      const memberCheckQuery = `
        SELECT COUNT(*) AS member_count 
        FROM communities_members 
        WHERE goal_id = $1 AND user_id = $2;
      `;
      const memberCheckResult = await client.query(memberCheckQuery, [
        goalId,
        userId,
      ]);
      const isMember = parseInt(memberCheckResult.rows[0].member_count, 10) > 0;

      if (isMember) {
        const updateMemberQuery = `
          UPDATE communities_members 
          SET saved_amount = saved_amount + $1, contribution = contribution + $1
          WHERE goal_id = $2 AND user_id = $3;
        `;
        await client.query(updateMemberQuery, [
          contributionAmount,
          goalId,
          userId,
        ]);
      } else {
        const insertMemberQuery = `
          INSERT INTO communities_members (goal_id, user_id, saved_amount, contribution) 
          VALUES ($1, $2, $3, $3);
        `;
        await client.query(insertMemberQuery, [
          goalId,
          userId,
          contributionAmount,
        ]);
      }

      const updateBalanceQuery = `
        UPDATE accounts 
        SET balance = balance - $1, updated_at = CURRENT_TIMESTAMP 
        WHERE user_id = $2;
      `;
      await client.query(updateBalanceQuery, [contributionAmount, userId]);

      const updateAccountQuery = `
        UPDATE accounts 
        SET allocated_funds = allocated_funds + $1, updated_at = CURRENT_TIMESTAMP 
        WHERE user_id = $2;
      `;
      await client.query(updateAccountQuery, [contributionAmount, userId]);

      // Insert notifications
      if (userId !== admin_id) {
        const notificationQuery = `
          INSERT INTO notifications (user_id, message, date) 
          VALUES ($1, $2, NOW()), ($3, $4, NOW());
        `;
        await client.query(notificationQuery, [
          userId,
          `Your contribution of ${contributionAmount} to ${title} has been recorded successfully.`,
          admin_id,
          `A contribution of ${contributionAmount} has been made to your goal ${title} by ${userId}.`,
        ]);
      } else {
        const notificationQuery = `
          INSERT INTO notifications (user_id, message, date) 
          VALUES ($1, $2, NOW());
        `;
        await client.query(notificationQuery, [
          userId,
          `Your contribution of ${contributionAmount} to ${title} has been recorded successfully.`,
        ]);
      }

      await client.query("COMMIT");

      // Send response immediately before sending emails
      res.status(200).json({ message: "Contribution successful." });

      // Send emails asynchronously
      (async () => {
        try {
          // Send email to contributor
          const userEmailResult = await pool.query(
            `SELECT email FROM users WHERE user_id = $1;`,
            [userId]
          );
          if (userEmailResult.rows.length > 0) {
            await sendEmail(
              userEmailResult.rows[0].email,
              "Contribution Successful",
              `Your contribution of ${contributionAmount} to ${title} was successful`,
              `<p>Your contribution of <strong>${contributionAmount}</strong> to <strong>${title}</strong> was successful.</p>`
            );
          }

          // Send email to admin (only if contributor is not the admin)
          if (userId !== admin_id) {
            const adminEmailResult = await pool.query(
              `SELECT email FROM users WHERE user_id = $1;`,
              [admin_id]
            );
            if (adminEmailResult.rows.length > 0) {
              await sendEmail(
                adminEmailResult.rows[0].email,
                "New Contribution Received",
                `User ${userId} contributed ${contributionAmount} to your goal: ${title}.`,
                `<p>User <strong>${userId}</strong> contributed <strong>${contributionAmount}</strong> to your goal: <strong>${title}</strong>.</p>`
              );
            }
          }
        } catch (emailError) {
          console.error("Failed to send email:", emailError);
        }
      })();
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Error during contribution:", error);
      res.status(400).json({ error: error.message });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Database connection error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.delete("/api/goals/:goalId/delete", async (req, res) => {
  const { goalId } = req.params;

  try {
    await pool.query("BEGIN");

    const goalResult = await pool.query(
      "SELECT saved_amount, user_id FROM goals WHERE goal_id = $1",
      [goalId]
    );

    if (goalResult.rowCount === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ message: "Goal not found" });
    }

    const { saved_amount, user_id } = goalResult.rows[0];

    const communityMembersResult = await pool.query(
      "SELECT user_id, saved_amount FROM communities_members WHERE goal_id = $1",
      [goalId]
    );

    if (communityMembersResult.rowCount > 0) {
      const communityMembers = communityMembersResult.rows;

      for (const member of communityMembers) {
        await pool.query(
          "UPDATE accounts SET balance = balance + $1 WHERE user_id = $2",
          [member.saved_amount, member.user_id]
        );
        await pool.query(
          "UPDATE accounts SET allocated_funds = allocated_funds - $1 WHERE user_id = $2",
          [member.saved_amount, member.user_id]
        );
      }
    }

    const deleteResult = await pool.query(
      "DELETE FROM goals WHERE goal_id = $1",
      [goalId]
    );

    if (deleteResult.rowCount === 0) {
      await pool.query("ROLLBACK");
      return res.status(500).json({ message: "Error deleting goal" });
    }

    await pool.query("COMMIT");

    res
      .status(200)
      .json({ message: "Goal deleted and funds reallocated successfully" });
  } catch (error) {
    await pool.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ message: "Error deleting goal" });
  }
});

app.post("/api/goal/:goalId/withdraw", async (req, res) => {
  const { userId, amount } = req.body;
  const { goalId } = req.params;
  try {
    // Fetch goal details
    const goal = await pool.query("SELECT * FROM goals WHERE goal_id = $1", [
      goalId,
    ]);
    if (!goal.rows.length)
      return res.status(404).json({ message: "Goal not found" });

    const { title } = goal.rows[0];

    const savedAmount = goal.rows[0].saved_amount;
    if (amount > savedAmount)
      return res.status(400).json({ message: "Insufficient funds" });

    // Fetch goal members and their roles
    const members = await pool.query(
      "SELECT user_id, saved_amount, goal_role FROM communities_members WHERE goal_id = $1",
      [goalId]
    );

    let adminId;
    if (members.rows.length) {
      for (const member of members.rows) {
        if (member.goal_role === "admin") {
          adminId = member.user_id;
        }
        const userShare = (member.saved_amount / savedAmount) * amount; // Deduct only proportionally
        await pool.query(
          "UPDATE communities_members SET saved_amount = GREATEST(saved_amount - $1, 0) WHERE user_id = $2 AND goal_id = $3",
          [userShare, member.user_id, goalId]
        );

        // Deduct from allocated funds of the user
        await pool.query(
          "UPDATE accounts SET allocated_funds = GREATEST(allocated_funds - $1, 0) WHERE user_id = $2",
          [userShare, member.user_id]
        );
      }
    }

    // Deduct amount from goal's saved amount
    await pool.query(
      "UPDATE goals SET saved_amount = saved_amount - $1 WHERE goal_id = $2",
      [amount, goalId]
    );

    // Update user's balance funds
    await pool.query(
      "UPDATE accounts SET balance = balance + $1 WHERE user_id = $2",
      [amount, userId]
    );

    // Insert notifications
    for (const member of members.rows) {
      if (member.user_id !== adminId) {
        await pool.query(
          "INSERT INTO notifications (user_id, message, date) VALUES ($1, $2, NOW())",
          [
            member.user_id,
            `The admin has withdrawn ${amount} from the goal ${title}.`,
          ]
        );
      }
    }
    await pool.query(
      "INSERT INTO notifications (user_id, message, date) VALUES ($1, $2, NOW())",
      [
        adminId,
        `Your withdrawal of ${amount} from goal ${title} was successful.`,
      ]
    );

    // Send response immediately before sending emails
    res.json({
      message: `Withdrawal of ${amount} successful. Funds added to balance funds.`,
    });

    // Send emails asynchronously
    (async () => {
      try {
        // Email to admin
        const adminEmailResult = await pool.query(
          "SELECT email FROM users WHERE user_id = $1",
          [adminId]
        );
        if (adminEmailResult.rows.length > 0) {
          await sendEmail(
            adminEmailResult.rows[0].email,
            "Withdrawal Successful",
            `Your withdrawal of ${amount} from goal ${title} was successful.`,
            `<p>Your withdrawal of <strong>${amount}</strong> from goal <strong>${title}</strong> was successful.</p>`
          );
        }

        // Email to members
        for (const member of members.rows) {
          if (member.user_id !== adminId) {
            const memberEmailResult = await pool.query(
              "SELECT email FROM users WHERE user_id = $1",
              [member.user_id]
            );
            if (memberEmailResult.rows.length > 0) {
              await sendEmail(
                memberEmailResult.rows[0].email,
                "Goal Withdrawal Notification",
                `The admin has withdrawn ${amount} from goal ${title}.`,
                `<p>The admin has withdrawn <strong>${amount}</strong> from goal <strong>${title}</strong>.</p>`
              );
            }
          }
        }
      } catch (emailError) {
        console.error("Failed to send email:", emailError);
      }
    })();
  } catch (error) {
    console.error("Withdrawal error:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
});

app.post("/api/goals/:goalId/members", async (req, res) => {
  const { goalId } = req.params;
  const { userId } = req.body;

  try {
    // Check if goal exists
    const goalResult = await pool.query(
      "SELECT * FROM goals WHERE goal_id = $1",
      [goalId]
    );
    if (goalResult.rows.length === 0) {
      return res.status(404).json({ error: "Goal not found" });
    }

    // Check if user exists
    const userResult = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const user = userResult.rows[0];

    // Check if user is already a member
    const memberCheck = await pool.query(
      "SELECT * FROM communities_members WHERE goal_id = $1 AND user_id = $2",
      [goalId, userId]
    );
    if (memberCheck.rows.length > 0) {
      return res
        .status(400)
        .json({ error: "User is already a member of this goal" });
    }

    // Insert new member with contribution column
    const query = `
      INSERT INTO communities_members (goal_id, user_id, saved_amount, contribution, joined_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const savedAmount = 0;
    const contribution = 0;
    await pool.query(query, [goalId, userId, savedAmount, contribution]);

    res.status(201).json({
      message: "Member added successfully",
      member: user,
    });
  } catch (error) {
    console.error("Error adding member:", error);
    res
      .status(500)
      .json({ error: "Internal server error. Please try again later." });
  }
});

app.delete("/api/goals/:goalId/members/:userId", async (req, res) => {
  const { goalId, userId } = req.params;

  try {
    await pool.query("BEGIN");
    const memberResult = await pool.query(
      "SELECT saved_amount FROM communities_members WHERE goal_id = $1 AND user_id = $2",
      [goalId, userId]
    );

    if (memberResult.rowCount === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ message: "Member not found in the goal" });
    }

    const { saved_amount } = memberResult.rows[0];

    await pool.query(
      "UPDATE accounts SET balance = balance + $1 WHERE user_id = $2",
      [saved_amount, userId]
    );

    await pool.query(
      "UPDATE accounts SET allocated_funds = allocated_funds - $1 WHERE user_id = $2",
      [saved_amount, userId]
    );
    await pool.query(
      "UPDATE goals SET saved_amount = saved_amount - $1 WHERE goal_id = $2",
      [saved_amount, goalId]
    );

    const deleteResult = await pool.query(
      "DELETE FROM communities_members WHERE goal_id = $1 AND user_id = $2",
      [goalId, userId]
    );

    if (deleteResult.rowCount === 0) {
      await pool.query("ROLLBACK");
      return res
        .status(500)
        .json({ message: "Error removing member from the goal" });
    }

    await pool.query("COMMIT");

    res.status(200).json({
      message:
        "Member removed from the goal and funds reallocated successfully",
    });
  } catch (error) {
    await pool.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ message: "Error removing member from the goal" });
  }
});

app.put(
  "/api/profiles/:userId/edit",
  upload.single("profilePic"),
  async (req, res) => {
    const { userId } = req.params;
    const { name, phone } = req.body;
    const profilePic = req.file
      ? `http://localhost:5000/uploads/${req.file.filename}`
      : null;

    if (!name || !phone) {
      return res
        .status(400)
        .json({ error: "Full name and phone are required." });
    }

    try {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const userQuery = `
        UPDATE users
        SET full_name = $1, phone = $2, profile_picture = COALESCE($3, profile_picture)
        WHERE user_id = $4
        RETURNING user_id, full_name, phone, profile_picture;
      `;

        const userResult = await client.query(userQuery, [
          name,
          phone,
          profilePic,
          userId,
        ]);

        await client.query("COMMIT");

        res.status(200).json({
          message: "Profile updated successfully.",
          user: userResult.rows[0],
        });
      } catch (error) {
        await client.query("ROLLBACK");
        console.error("Error updating profile:", error);
        res
          .status(500)
          .json({ error: error.message || "Internal server error." });
      } finally {
        client.release();
      }
    } catch (error) {
      res.status(500).json({ error: "Database connection error." });
    }
  }
);

app.put("/api/users/:userId/request-delete", async (req, res) => {
  const { userId } = req.params;

  try {
    const deleteRequestDate = new Date();
    const result = await pool.query(
      "UPDATE users SET delete_request_date = $1 WHERE user_id = $2 RETURNING *",
      [deleteRequestDate, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "Delete request processed successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Error processing delete request:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/accounts/:userId/toggle-two-step", async (req, res) => {
  const { userId } = req.params;
  const { twoStepEnabled } = req.body;

  try {
    await pool.query(
      "UPDATE accounts SET two_step_verification = $1 WHERE user_id = $2",
      [twoStepEnabled, userId]
    );
    res
      .status(200)
      .json({ message: "Two-step verification updated successfully" });
  } catch (error) {
    console.error("Error toggling two-step verification:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/users/:userId/change-password", async (req, res) => {
  const { userId } = req.params;
  const { currentPassword, newPassword } = req.body;

  try {
    const userResult = await pool.query(
      "SELECT password_hash FROM users WHERE user_id = $1",
      [userId]
    );
    if (userResult.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const currentHash = userResult.rows[0].password_hash;

    const isMatch = await bcrypt.compare(currentPassword, currentHash);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect current password" });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE user_id = $2", [
      newHash,
      userId,
    ]);
    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/users/:userId/request-info", async (req, res) => {
  const { userId } = req.params;

  try {
    const requestDate = new Date();
    await pool.query(
      "INSERT INTO account_info_requests (user_id, request_date) VALUES ($1, $2)",
      [userId, requestDate]
    );

    res
      .status(200)
      .json({ message: "Account information request submitted successfully" });
  } catch (error) {
    console.error("Error processing account info request:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/referrals/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const referrerResult = await pool.query(
      "SELECT user_id FROM users WHERE user_id = $1",
      [userId]
    );
    if (referrerResult.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    const referrerId = referrerResult.rows[0].user_id;

    const referralsResult = await pool.query(
      `SELECT u.full_name AS name,
              TO_CHAR(r.created_at, 'YYYY-MM-DD"T"HH24:MI:SS.MS') AS joined_date,
              u.account_status,
              r.redeemed
       FROM referrals r 
       JOIN users u ON r.referred_user_id = u.user_id 
       WHERE r.referrer_user_id = $1`,
      [referrerId]
    );

    const referrals = referralsResult.rows.map((referral) => ({
      name: referral.name,
      joined: Boolean(referral.name),
      joinedDate: referral.joined_date || null,
      accountStatus: referral.account_status,
      redeemed: referral.redeemed || false,
    }));

    const rewardsEarnedResult = await pool.query(
      `SELECT COUNT(*) * 25 AS rewardsEarned
       FROM referrals r
       WHERE r.referrer_user_id = $1
         AND r.redeemed = FALSE
         AND EXISTS (
           SELECT 1 FROM users u 
           WHERE u.user_id = r.referred_user_id 
             AND u.account_status = 'active'
         )`,
      [referrerId]
    );

    const rewardsEarned = rewardsEarnedResult.rows[0].rewardsearned || 0;
    const referralLink = `http://localhost:5173/register/step-1?ref=${userId}`;

    res.json({ referrals, rewardsEarned, referralLink });
  } catch (error) {
    console.error("Error fetching referrals:", error);
    res.status(500).json({ message: "Error fetching referrals" });
  }
});

app.post("/api/add-to-savings", async (req, res) => {
  const { userId, amount } = req.body;

  if (!userId || !amount) {
    return res
      .status(400)
      .json({ message: "User ID and amount are required." });
  }

  try {
    const checkRedeemed = await pool.query(
      `SELECT redeemed FROM referrals WHERE referrer_user_id = $1 AND redeemed = FALSE`,
      [userId]
    );

    if (checkRedeemed.rowCount < 0) {
      return res
        .status(400)
        .json({ message: "Rewards have already been redeemed." });
    }

    await pool.query(
      `UPDATE accounts SET balance = balance + $1 WHERE user_id = $2`,
      [amount, userId]
    );

    await pool.query(
      `UPDATE referrals SET redeemed = TRUE WHERE referrer_user_id = $1`,
      [userId]
    );

    res.status(200).json({ message: "Rewards added to savings successfully." });
  } catch (error) {
    console.error("Error adding rewards to savings:", error);
    res.status(500).json({ message: "Failed to add rewards to savings." });
  }
});

app.post("/api/feedback", async (req, res) => {
  const { userId, email, rating, feedback } = req.body;

  if (!rating || !feedback) {
    return res
      .status(400)
      .json({ message: "Rating and feedback are required." });
  }

  try {
    await pool.query(
      `INSERT INTO feedback (user_id, email, rating, feedback) 
           VALUES ($1, $2, $3, $4)`,
      [userId, email, rating, feedback]
    );
    res.status(201).json({ message: "Thank you for your feedback!" });
  } catch (error) {
    console.error("Error saving feedback:", error);
    res
      .status(500)
      .json({ message: "Failed to submit feedback. Please try again later." });
  }
});

app.post("/api/support", async (req, res) => {
  const { userId, email, message } = req.body;

  if (!email || !message) {
    return res.status(400).json({ message: "Email and message are required." });
  }

  try {
    await pool.query(
      `INSERT INTO support_messages (user_id, email, message) 
           VALUES ($1, $2, $3)`,
      [userId, email, message]
    );
    res.status(201).json({
      message:
        "Your message has been sent. Our support team will contact you shortly.",
    });
  } catch (error) {
    console.error("Error saving support message:", error);
    res.status(500).json({
      message: "Failed to send your message. Please try again later.",
    });
  }
});

app.get("/api/notifications/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const notifications = await pool.query(
      "SELECT * FROM notifications WHERE user_id = $1 ORDER BY date DESC",
      [userId]
    );
    res.json(notifications.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

app.post("/api/notifications", async (req, res) => {
  const { user_id, message } = req.body;

  try {
    const newNotification = await pool.query(
      "INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *",
      [user_id, message]
    );
    res.json(newNotification.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});
app.put("/api/notifications/:id/mark-as-read", async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("UPDATE notifications SET is_read = TRUE WHERE id = $1", [
      id,
    ]);
    res.send("Notification marked as read");
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});
app.delete("/api/notifications/:id", async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM notifications WHERE id = $1", [id]);
    res.send("Notification removed");
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

app.get("/superadmin/totals", async (req, res) => {
  try {
    const totalUsersResults = await pool.query("SELECT COUNT(*) FROM users");
    const totalUsers = totalUsersResults.rows[0].count;

    const totalSavingsResults = await pool.query(
      "SELECT SUM(balance) FROM accounts"
    );
    const totalSavings = totalSavingsResults.rows[0].sum;

    const totalActiveUsersResults = await pool.query(
      "SELECT COUNT(*) FROM users WHERE account_status = 'active' "
    );
    const totalActiveUsers = totalActiveUsersResults.rows[0].count;

    const totalInactiveUsersResults = await pool.query(
      "SELECT COUNT(*) FROM users WHERE account_status = 'inactive' "
    );
    const totalInactiveUsers = totalInactiveUsersResults.rows[0].count;

    const totalIncompleteRegistrationsResults = await pool.query(
      "SELECT COUNT(*) FROM users WHERE registration_status != 'complete' "
    );
    const totalIncompleteRegistrations =
      totalIncompleteRegistrationsResults.rows[0].count;

    const totalSavingGoalsResults = await pool.query(
      "SELECT COUNT(*) FROM goals"
    );
    const totalGoals = totalSavingGoalsResults.rows[0].count;

    const totalFeedbacksResults = await pool.query(
      "SELECT COUNT(*) FROM feedback"
    );
    const totalFeedbacks = totalFeedbacksResults.rows[0].count;

    const totalSupportMessagesResults = await pool.query(
      "SELECT COUNT(*) FROM support_messages"
    );
    const totalSupportMessages = totalSupportMessagesResults.rows[0].count;

    const totalDeleteRequestsResults = await pool.query(
      "SELECT COUNT(*) FROM users WHERE delete_request_date IS NOT NULL"
    );
    const totalDeleteRequests = totalDeleteRequestsResults.rows[0].count;

    const totalAccountInfoRequestsResults = await pool.query(
      "SELECT COUNT(*) FROM account_info_requests"
    );
    const totalAccountInfoRequests =
      totalAccountInfoRequestsResults.rows[0].count;

    const totalLoanRequestsResults = await pool.query(
      "SELECT COUNT(*) FROM loans WHERE status='Pending' "
    );
    const totalLoanRequests = totalLoanRequestsResults.rows[0].count;

    res.json({
      totalUsers,
      totalSavings,
      totalActiveUsers,
      totalInactiveUsers,
      totalIncompleteRegistrations,
      totalGoals,
      totalDeleteRequests,
      totalFeedbacks,
      totalSupportMessages,
      totalAccountInfoRequests,
      totalLoanRequests,
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "users" });
  }
});
app.get("/superadmin/users", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT users.id, users.full_name, users.user_id, users.email, users.phone, 
              accounts.balance, accounts.loan_limit 
       FROM users 
       LEFT JOIN accounts ON users.user_id = accounts.user_id 
       ORDER BY users.id DESC`
    );
    res.json({
      users: result.rows,
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Error fetching users" });
  }
});

app.put("/superadmin/users/:id", async (req, res) => {
  const { id } = req.params;
  const { full_name, email, phone, loan_limit } = req.body;

  try {
    const userCheck = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [id]
    );
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    await pool.query(
      "UPDATE users SET full_name = $1, email = $2, phone = $3 WHERE user_id = $4",
      [full_name, email, phone, id]
    );

    if (loan_limit !== undefined) {
      await pool.query(
        "UPDATE accounts SET loan_limit = $1 WHERE user_id = $2",
        [loan_limit, id]
      );

      const userEmail = userCheck.rows[0].email;

      // Send email asynchronously
      (async () => {
        try {
          await sendEmail(
            userEmail,
            "Loan Limit Updated",
            `Your loan limit has been updated to ${loan_limit}.`
          );
        } catch (error) {
          console.error("Failed to send email:", error);
        }
      })();

      await pool.query(
        "INSERT INTO notifications (user_id, message, date) VALUES ($1, $2, NOW())",
        [id, `Your loan limit has been updated to ${loan_limit}.`]
      );
    }

    res.json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/superadmin/active-users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,full_name,user_id,email,phone FROM users WHERE account_status = 'active' ORDER BY id DESC"
    );
    res.json({
      activeUsers: result.rows,
    });
  } catch (err) {
    console.error("Error fetching active users:", err);
    res.status(500).json({ message: "active users" });
  }
});

app.get("/superadmin/inactive-users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,full_name,user_id,email,phone FROM users WHERE account_status = 'inactive' ORDER BY id DESC"
    );
    res.json({
      inactiveUsers: result.rows,
    });
  } catch (err) {
    console.error("Error fetching inactive users:", err);
    res.status(500).json({ message: "inactive users" });
  }
});

app.get("/superadmin/incomplete-registrations", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,full_name,user_id,email,phone,registration_status FROM users WHERE registration_status != 'complete' ORDER BY id DESC"
    );
    res.json({
      incompleteRegistrations: result.rows,
    });
  } catch (err) {
    console.error("Error fetching incomplete registrations:", err);
    res.status(500).json({ message: "incomplete registrations" });
  }
});

app.get("/superadmin/saving-goals", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM goals ORDER BY goal_id DESC"
    );
    res.json({
      goals: result.rows,
    });
  } catch (err) {
    console.error("Error fetching saving goals:", err);
    res.status(500).json({ message: "saving goals" });
  }
});

app.get("/superadmin/delete-requests", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT full_name,phone, delete_request_date FROM users WHERE delete_request_date IS NOT NULL ORDER BY id DESC"
    );

    res.json({
      deleteRequests: result.rows,
    });
  } catch (err) {
    console.error("Error fetching delete requests:", err);
    res.status(500).json({ message: "Failed to fetch delete requests" });
  }
});

app.get("/superadmin/feedbacks", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM feedback ORDER BY id DESC");
    res.json({
      feedbacks: result.rows,
    });
  } catch (err) {
    console.error("Error fetching feedbacks:", err);
    res.status(500).json({ message: "feedbacks" });
  }
});

app.get("/superadmin/support-inquiries", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM support_messages ORDER BY id DESC"
    );
    res.json({
      supportMessages: result.rows,
    });
  } catch (err) {
    console.error("Error fetching support messages:", err);
    res.status(500).json({ message: "support messages" });
  }
});

app.get("/superadmin/account-info-requests", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM account_info_requests ORDER BY id DESC"
    );
    res.json({
      infoRequests: result.rows,
    });
  } catch (err) {
    console.error("Error fetching info requests:", err);
    res.status(500).json({ message: "info requests" });
  }
});

app.get("/superadmin/loan-requests", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM loans ORDER BY id DESC");
    res.json({
      loanRequests: result.rows,
    });
  } catch (err) {
    console.error("Error fetching loan requests:", err);
    res.status(500).json({ message: "loan requests" });
  }
});

app.get("/api/loan/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const loanHistoryResult = await pool.query(
      `
      SELECT id, amount, duration, purpose, status, repayment_amount, repayment_due_date, created_at 
      FROM loans 
      WHERE user_id = $1 
      ORDER BY created_at DESC;
    `,
      [userId]
    );
    const loans = loanHistoryResult.rows;

    const loanLimitResult = await pool.query(
      `
      SELECT loan_limit 
      FROM accounts 
      WHERE user_id = $1;
    `,
      [userId]
    );

    if (loanLimitResult.rowCount === 0) {
      return res.status(404).json({ message: "User account not found." });
    }

    const loanLimit = loanLimitResult.rows[0].loan_limit;

    res.status(200).json({
      loans,
      loanLimit,
    });
  } catch (error) {
    console.error("Error fetching loan data:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/api/superadmin/user-details/:userId", async (req, res) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    const userResult = await pool.query(
      `SELECT users.id, users.full_name, users.user_id, users.email, users.phone, 
              accounts.balance, accounts.loan_limit, user_ids.front_id_path, user_ids.back_id_path
       FROM users 
       LEFT JOIN user_ids ON users.user_id = user_ids.user_id 
       LEFT JOIN accounts ON users.user_id = accounts.user_id 
         WHERE users.user_id = $1`,
      [userId]
    );
    const user = userResult.rows[0];
    res.status(200).json({
      user,
    });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/api/loans/borrow", async (req, res) => {
  const { userId, amount, duration, purpose } = req.body;

  try {
    if (!userId || !amount || !duration || !purpose) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const parsedAmount = parseFloat(amount);
    const activeLoanQuery = `
      SELECT COUNT(*) AS active_loans 
      FROM loans 
      WHERE user_id = $1 AND status IN ('Pending', 'Approved');
    `;
    const activeLoanResult = await pool.query(activeLoanQuery, [userId]);
    if (parseInt(activeLoanResult.rows[0].active_loans) > 0) {
      return res.status(400).json({
        message: "You have an active loan and cannot request another.",
      });
    }
    const loanLimitQuery = `
      SELECT loan_limit 
      FROM accounts 
      WHERE user_id = $1;
    `;
    const loanLimitResult = await pool.query(loanLimitQuery, [userId]);
    const loanLimit = parseFloat(loanLimitResult.rows[0].loan_limit);

    if (parsedAmount > loanLimit) {
      return res.status(400).json({
        message: `Loan request exceeds your current loan limit of $${loanLimit}.`,
      });
    }
    const now = new Date();
    let interestRate = 0;
    let repaymentDate = new Date();

    if (duration.includes("days")) {
      const days = parseInt(duration);
      repaymentDate.setDate(now.getDate() + days);
      interestRate = days <= 10 ? 0 : 0.05;
    } else if (duration.includes("weeks")) {
      const weeks = parseInt(duration);
      repaymentDate.setDate(now.getDate() + weeks * 7);
      interestRate = 0.07;
    } else if (duration.includes("months")) {
      const months = parseInt(duration);
      repaymentDate.setMonth(now.getMonth() + months);
      interestRate = 0.1;
    }

    const repaymentAmount = (parsedAmount * (1 + interestRate)).toFixed(2);

    const newLoanQuery = `
      INSERT INTO loans (user_id, amount, duration, purpose, repayment_amount, repayment_due_date, status) 
      VALUES ($1, $2, $3, $4, $5, $6, 'Pending') 
      RETURNING *;
    `;
    const newLoan = await pool.query(newLoanQuery, [
      userId,
      parsedAmount,
      duration,
      purpose,
      repaymentAmount,
      repaymentDate,
    ]);

    res.status(201).json({
      message: "Loan request submitted successfully!",
      loan: newLoan.rows[0],
    });
  } catch (error) {
    console.error("Error creating loan:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.post("/loans/:loanId/repay", async (req, res) => {
  const { loanId } = req.params;
  const { userId, repaymentAmount } = req.body;

  try {
    const loanQuery = `
      SELECT id, user_id, repayment_amount, status 
      FROM loans 
      WHERE id = $1 AND user_id = $2;
    `;
    const loanResult = await pool.query(loanQuery, [loanId, userId]);
    const loan = loanResult.rows[0];

    if (!loan) {
      return res.status(404).json({ message: "Loan not found." });
    }

    if (loan.status !== "Approved") {
      return res
        .status(400)
        .json({ message: "Only approved loans can be repaid." });
    }

    const accountQuery = `
      SELECT balance
      FROM accounts 
      WHERE user_id = $1;
    `;
    const accountResult = await pool.query(accountQuery, [userId]);
    const balance = accountResult.rows[0];

    if (balance < repaymentAmount) {
      return res
        .status(400)
        .json({ message: "Insufficient funds in account to repay the loan." });
    }

    const updateBalanceQuery = `
      UPDATE accounts 
      SET balance = balance - $1 
      WHERE user_id = $2;
    `;
    await pool.query(updateBalanceQuery, [repaymentAmount, userId]);

    const updatedRepaymentAmount = loan.repayment_amount - repaymentAmount;
    const updateLoanQuery = `
      UPDATE loans 
      SET repayment_amount = $1 
      WHERE id = $2;
    `;
    await pool.query(updateLoanQuery, [updatedRepaymentAmount, loanId]);

    if (updatedRepaymentAmount <= 0) {
      const updateLoanStatusQuery = `
        UPDATE loans 
        SET status = 'Repaid' 
        WHERE id = $1;
      `;
      await pool.query(updateLoanStatusQuery, [loanId]);
    }

    res.status(200).json({ message: "Loan repayment processed successfully!" });
  } catch (error) {
    console.error("Error processing loan repayment:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.put("/loans/:loanId/approve", async (req, res) => {
  const { loanId } = req.params;

  try {
    const loanQuery = `
      SELECT user_id, amount, status 
      FROM loans 
      WHERE id = $1;
    `;
    const loanResult = await pool.query(loanQuery, [loanId]);
    const loan = loanResult.rows[0];

    if (!loan) {
      return res.status(404).json({ message: "Loan request not found." });
    }

    if (loan.status !== "Pending") {
      return res
        .status(400)
        .json({ message: "Only pending loans can be approved." });
    }

    const userId = loan.user_id;
    const approveLoanQuery = `
      UPDATE loans 
      SET status = 'Approved' 
      WHERE id = $1 
      RETURNING *;
    `;
    const approvedLoan = await pool.query(approveLoanQuery, [loanId]);

    const updateBalanceQuery = `
      UPDATE accounts 
      SET balance = balance + $1
      WHERE user_id = $2;
    `;
    await pool.query(updateBalanceQuery, [loan.amount, userId]);

    res.status(200).json({
      message: "Loan approved successfully, and balance updated.",
      loan: approvedLoan.rows[0],
    });
  } catch (error) {
    console.error("Error approving loan:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.put("/loans/:loanId/decline", async (req, res) => {
  const { loanId } = req.params;

  try {
    const query = `
      UPDATE loans 
      SET status = 'Declined'
      WHERE id = $1
      RETURNING *;
    `;
    const result = await pool.query(query, [loanId || null]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Loan request not found." });
    }

    res.status(200).json({
      message: "Loan request declined successfully.",
      loan: result.rows[0],
    });
  } catch (error) {
    console.error("Error declining loan request:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/api/interests/last-update", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT MAX(last_update_date) AS last_update 
       FROM interests`
    );

    const lastUpdate = result.rows[0]?.last_update;

    if (!lastUpdate) {
      return res.status(200).json({ lastUpdate: null });
    }

    res.status(200).json({ lastUpdate });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch the last update date." });
  }
});

app.post("/api/interests/update", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT i.id, i.user_id, i.interest_earned, i.last_update_date, a.balance, a.allocated_funds 
       FROM interests i
       JOIN accounts a ON i.user_id = a.user_id`
    );

    const today = new Date();
    let updates = [];

    for (let row of result.rows) {
      const lastUpdate = row.last_update_date
        ? new Date(row.last_update_date)
        : today;

      const daysPassed = Math.floor(
        (today - lastUpdate) / (1000 * 60 * 60 * 24)
      );

      if (daysPassed > 0) {
        const totalFunds = row.balance + row.allocated_funds;
        const compoundedRate = (1 + DAILY_RATE) ** daysPassed - 1;
        const interest = totalFunds * compoundedRate;

        if (!isNaN(interest) && interest > 0) {
          updates.push(
            pool.query(
              `UPDATE interests 
               SET interest_earned = interest_earned + $1, 
                   last_update_date = $2 
               WHERE id = $3`,
              [interest, today, row.id]
            )
          );

          updates.push(
            pool.query(
              `UPDATE accounts 
               SET balance = balance + $1 
               WHERE user_id = $2`,
              [interest, row.user_id]
            )
          );
        }
      } else if (daysPassed === 0) {
        updates.push(
          pool.query(
            `UPDATE interests 
             SET last_update_date = $1 
             WHERE id = $2`,
            [today, row.id]
          )
        );
      }
    }

    await Promise.all(updates);

    res.status(200).json({ message: "Interests updated successfully." });
  } catch (error) {
    console.error("Error updating interests:", error);
    res.status(500).json({ error: "Failed to update interests." });
  }
});

app.get("/api/interests/performance/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const today = new Date();
    const periods = ["3months", "6months", "1year", "2years"];
    let performanceData = [];
    const periodRanges = {
      "3months": new Date(today.setMonth(today.getMonth() - 3)),
      "6months": new Date(today.setMonth(today.getMonth() - 6)),
      "1year": new Date(today.setFullYear(today.getFullYear() - 1)),
      "2years": new Date(today.setFullYear(today.getFullYear() - 2)),
    };

    const todayDate = new Date();

    const result = await pool.query(
      `SELECT i.interest_earned, i.last_update_date, a.balance, a.allocated_funds
       FROM interests i
       JOIN accounts a ON i.user_id = a.user_id
       WHERE i.user_id = $1`,
      [userId]
    );

    periods.forEach((period) => {
      const startDate = periodRanges[period];
      let totalInterest = 0;
      let totalBalance = 0;

      result.rows.forEach((row) => {
        const lastUpdate = row.last_update_date
          ? new Date(row.last_update_date)
          : todayDate;

        if (lastUpdate >= startDate && lastUpdate <= todayDate) {
          totalInterest += parseFloat(row.interest_earned || 0);
          totalBalance +=
            parseFloat(row.balance || 0) + parseFloat(row.allocated_funds || 0);
        }
      });

      performanceData.push({
        period: period,
        interest: totalInterest,
        total: totalBalance,
      });
    });

    res.status(200).json({
      message: "Investment performance fetched successfully",
      performance: performanceData,
    });
  } catch (error) {
    console.error("Error fetching investment performance:", error);
    res.status(500).json({ error: "Failed to fetch investment performance." });
  }
});

app.delete("/api/superadmin/users/delete/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const deleteUserQuery = "DELETE FROM users WHERE user_id = $1 RETURNING *";
    const deletedUser = await pool.query(deleteUserQuery, [userId]);

    if (deletedUser.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
