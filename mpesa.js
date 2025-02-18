const axios = require("axios");
require("dotenv").config();  // Load environment variables from .env file

const processSTKPush = async (phoneNumber, amount) => {
  try {
    const response = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: process.env.MPESA_PASSWORD,
        Timestamp: "20250217112048",  // Ideally, generate this dynamically
        TransactionType: "CustomerPayBillOnline",
        Amount: amount,
        PartyA: 254708374149, // This can also be dynamic if needed
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: phoneNumber, // Dynamic Phone Number
        CallBackURL: process.env.CALLBACK_URL,
        AccountReference: process.env.ACCOUNT_REFERENCE,
        TransactionDesc: process.env.TRANSACTION_DESC,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.MPESA_ACCESS_TOKEN}`,
        },
      }
    );

    return response.data; // Return M-Pesa API response
  } catch (error) {
    console.error("M-Pesa STK Push Error:", error.response?.data || error.message);
    throw new Error("Failed to initiate M-Pesa STK Push.");
  }
};

// Export STK Push function
module.exports = { processSTKPush };
