const ALLOWED_HOSTNAMES = ["robert-cv.web.app", "robert-cv.firebaseapp.com", "localhost", "127.0.0.1"];
const DEFAULT_SCORE_THRESHOLD = 0.5;
const SENSITIVE_SCORE_THRESHOLD = 0.6; // Higher threshold for deletion/write actions

async function createAssessment({
  token = "",
  expectedAction = "portfolio_access",
}) {
  return verifyRecaptchaToken(token, expectedAction);
}

async function verifyRecaptchaToken(token, expectedAction = ["portfolio_access", "fetch_header", "fetch_experience", "fetch_education", "delete_user_data"]) {
  if (!token) {
    return {
      valid: false,
      score: 0.0,
      requiredThreshold: DEFAULT_SCORE_THRESHOLD,
      action: null,
      expectedAction: expectedAction,
      actionMatch: false,
      hostname: null,
      hostnameMatch: false,
      reasons: ["MISSING_TOKEN"],
      hasBotReason: true,
      isLegitimate: false,
      challengeTs: null,
      errorCodes: ["MISSING_TOKEN"],
    };
  }

  try {
    let isValid = false;
    let action = null;
    let hostname = null;
    let score = 0.0;
    let reasons = [];
    let verificationMethod = "none";

    //  reCAPTCHA Enterprise Assessment REST API
    try {
      const { GoogleAuth } = require("google-auth-library");
      const auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
      const client = await auth.getClient();
      const tokenRes = await client.getAccessToken();
      const accessToken = typeof tokenRes === "string" ? tokenRes : (tokenRes && tokenRes.token ? tokenRes.token : null);

      const firstExpectedAction = Array.isArray(expectedAction) ? expectedAction[0] : expectedAction;

      const enterpriseRes = await fetch(`https://recaptchaenterprise.googleapis.com/v1/projects/${PROJECT_ID}/assessments`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          event: {
            token: token,
            siteKey: RECAPTCHA_SITE_KEY,
            expectedAction: firstExpectedAction,
          }
        }),
      });

      if (enterpriseRes.ok) {
        const entData = await enterpriseRes.json();
        const tokenProps = entData.tokenProperties || {};
        const riskAnalysis = entData.riskAnalysis || {};

        if (tokenProps.valid === true) {
          isValid = true;
          action = tokenProps.action || null;
          hostname = tokenProps.hostname || null;
          score = typeof riskAnalysis.score === "number" ? riskAnalysis.score : 0.0;
          reasons = Array.isArray(riskAnalysis.reasons) ? riskAnalysis.reasons : [];
          verificationMethod = "enterprise_api";
        } else {
          reasons = [tokenProps.invalidReason || "INVALID_TOKEN"];
          console.warn("Enterprise API token invalid:", tokenProps.invalidReason, entData);
        }
      } else {
        const errTxt = await enterpriseRes.text();
        console.warn("Enterprise API HTTP error:", enterpriseRes.status, errTxt);
      }
    } catch (eErr) {
      console.warn("Enterprise API error:", eErr.message || eErr);
    }

    //  Action Matching
    let actionMatch = true;
    if (expectedAction) {
      if (Array.isArray(expectedAction)) {
        actionMatch = action ? expectedAction.includes(action) : false;
      } else {
        actionMatch = action === expectedAction;
      }
    }

    //  Hostname Validation
    const hostnameMatch = hostname ? ALLOWED_HOSTNAMES.some(allowed => hostname.toLowerCase().includes(allowed.toLowerCase())) : true;

    //  Action-Specific Thresholding
    const isSensitive = action === "delete_user_data";
    const requiredThreshold = isSensitive ? SENSITIVE_SCORE_THRESHOLD : DEFAULT_SCORE_THRESHOLD;

    //  Score & Reason Code Evaluation
    const scorePassed = isValid ? (score >= requiredThreshold) : false;
    const botReasonCodes = ["AUTOMATION", "UNEXPECTED_ENVIRONMENT", "TOO_MUCH_TRAFFIC", "UNEXPECTED_USAGE_PATTERNS", "INVALID_KEYS"];
    const hasBotReason = reasons.some(r => botReasonCodes.includes(String(r).toUpperCase()));

    // Final Combined Legitimacy
    const isLegitimate = isValid && actionMatch && hostnameMatch && scorePassed && !hasBotReason;

    return {
      valid: isValid,
      score: score,
      requiredThreshold: requiredThreshold,
      action: action,
      expectedAction: expectedAction,
      actionMatch: actionMatch,
      hostname: hostname,
      hostnameMatch: hostnameMatch,
      reasons: reasons,
      hasBotReason: hasBotReason,
      isLegitimate: isLegitimate,
      verificationMethod: verificationMethod,
      errorCodes: reasons,
    };
  } catch (err) {
    console.warn("reCAPTCHA verification error:", err);
    return {
      valid: false,
      score: 0.0,
      requiredThreshold: DEFAULT_SCORE_THRESHOLD,
      action: null,
      expectedAction: expectedAction,
      actionMatch: false,
      hostnameMatch: false,
      hasBotReason: true,
      isLegitimate: false,
      verificationMethod: "none",
      errorCodes: [err.message || "VERIFICATION_ERROR"],
    };
  }
}
