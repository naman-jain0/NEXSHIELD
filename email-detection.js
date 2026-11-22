document.addEventListener("DOMContentLoaded", function () {

    const detectBtn = document.querySelector(".detect-btn");
    const resetBtn = document.querySelector(".reset-btn");
    const emailInput = document.querySelector("#email-content");
    const scanner = document.querySelector(".email-scanner");

    if (!detectBtn || !resetBtn || !emailInput || !scanner) {
        console.error("NEXSHIELD: Email scanner elements not found.");
        return;
    }

    // Create result box automatically
    const resultBox = document.createElement("div");
    resultBox.className = "scan-result";
    resultBox.setAttribute("aria-live", "polite");
    scanner.appendChild(resultBox);














    function analyzeEmail(email) {

    const text = email.toLowerCase();
    let score = 0;
    let reasons = [];

    // Check each rule
    function check(pattern, points, reason) {
        if (pattern.test(text)) {
            score += points;
            reasons.push(reason);
        }
    }

    // =====================================
    // 1. OTP, PASSWORD AND IDENTITY FRAUD
    // =====================================

    check(
        /(share|send|provide|tell|enter|submit).{0,35}(otp|one.time.password|verification code)/,
        5,
        "Request for OTP or verification code"
    );

    check(
        /(otp|verification code).{0,35}(share|send|provide|enter)/,
        5,
        "Suspicious OTP verification request"
    );

    check(
        /(password|pin|cvv|atm pin|upi pin).{0,40}(share|send|provide|enter|confirm)/,
        5,
        "Request for confidential banking credentials"
    );

    check(
        /(aadhaar|aadhar|pan card).{0,45}(suspend|block|deactivat|expire|verify)/,
        3,
        "Possible fake identity document warning"
    );

    check(
        /(kyc|identity).{0,40}(update|verify|suspend|block|expire)/,
        3,
        "Suspicious KYC or identity verification"
    );

    // =====================================
    // 2. BANK AND CUSTOMER SUPPORT FRAUD
    // =====================================

    check(
        /(bank|account).{0,45}(blocked|suspended|frozen|closed|deactivated)/,
        3,
        "Possible fake bank account warning"
    );

    check(
        /(verify|confirm|update|provide).{0,40}(account details|bank details|personal details)/,
        3,
        "Request for sensitive account information"
    );

    check(
        /(customer support|customer care|bank officer|bank manager).{0,60}(otp|password|pin|payment|account details)/,
        4,
        "Possible customer support impersonation"
    );

    check(
        /(payment issue|payment problem).{0,50}(verify|account|details|payment)/,
        2,
        "Suspicious payment verification request"
    );

    // =====================================
    // 3. PHISHING AND FAKE LOGIN EMAILS
    // =====================================

    check(
        /(click|visit|open).{0,35}(link|button|website).{0,50}(verify|login|account|password|bank)/,
        3,
        "Possible phishing link instruction"
    );

    check(
        /(login|sign in|verify account).{0,40}(immediately|required|suspended|blocked)/,
        3,
        "Suspicious login or account verification demand"
    );

    check(
        /(unusual activity|unauthorized access|suspicious login)/,
        2,
        "Account security warning requiring independent verification"
    );

    // =====================================
    // 4. LOTTERY AND PRIZE FRAUD
    // =====================================

    check(
        /(you have won|lucky winner|selected as winner|won a lottery)/,
        3,
        "Possible fake lottery announcement"
    );

    check(
        /(free|won|selected|congratulations).{0,45}(iphone|mobile|phone|gift|prize|reward|lottery)/,
        3,
        "Unexpected prize or gift offer"
    );

    check(
        /(claim|receive).{0,35}(prize|reward|gift|lottery|winnings)/,
        2,
        "Suspicious prize claim request"
    );

    // =====================================
    // 5. ADVANCE FEE AND PAYMENT FRAUD
    // =====================================

    check(
        /(pay|send|deposit).{0,35}(delivery|processing|registration|security|refundable).{0,20}(fee|charge|amount|money)?/,
        3,
        "Possible advance fee fraud"
    );

    check(
        /(delivery|shipping|processing|registration).{0,20}(fee|charges|payment)/,
        2,
        "Unexpected payment or processing fee"
    );

    check(
        /(pay|send|transfer).{0,30}(₹|rs\.?|rupees|inr)\s?\d+/,
        2,
        "Direct request for money"
    );

    // =====================================
    // 6. JOB AND EMPLOYMENT SCAMS
    // =====================================

    check(
        /(work from home|part.time job|job offer|job vacancy|online job)/,
        1,
        "Unsolicited employment offer"
    );

    check(
        /(registration fee|training fee|joining fee).{0,40}(job|work|salary|interview)?/,
        3,
        "Possible fake job registration fee"
    );

    check(
        /(earn|salary|income).{0,35}(daily|weekly|per day|guaranteed|without work)/,
        3,
        "Unrealistic earning promise"
    );

    // =====================================
    // 7. INVESTMENT AND LOAN SCAMS
    // =====================================

    check(
        /(guaranteed|fixed|sure).{0,30}(profit|return|income)/,
        3,
        "Unrealistic guaranteed investment returns"
    );

    check(
        /(double|triple).{0,25}(money|investment|amount)/,
        3,
        "Possible investment doubling scam"
    );

    check(
        /(invest|investment|trading).{0,40}(guaranteed profit|daily profit|high return)/,
        3,
        "Suspicious investment promise"
    );

    check(
        /(instant loan|pre.approved loan|loan approved).{0,40}(fee|payment|deposit|processing)/,
        3,
        "Possible fraudulent loan fee"
    );

    // =====================================
    // 8. UPI AND PAYMENT REFUND SCAMS
    // =====================================

    check(
        /(accidentally|mistakenly|wrongly).{0,50}(transferred|sent|credited).{0,40}(money|amount|account|upi)?/,
        4,
        "Possible accidental money transfer scam"
    );

    check(
        /(send|transfer|return|refund|pay).{0,40}(back|money|amount|upi|account)/,
        3,
        "Suspicious money return or transfer request"
    );

    check(
        /(upi id|upi address|payment id).{0,45}(send|transfer|return|refund|pay)/,
        3,
        "Suspicious UPI payment instruction"
    );

    check(
        /(collect request|approve payment|receive refund).{0,40}(upi|pin|payment|request)?/,
        3,
        "Possible fraudulent UPI payment request"
    );

    // =====================================
    // 9. COURIER AND DELIVERY SCAMS
    // =====================================

    check(
        /(parcel|package|courier|delivery).{0,50}(held|blocked|failed|address|customs|fee|payment)/,
        2,
        "Suspicious parcel or delivery notification"
    );

    check(
        /(delivery failed|address incomplete|parcel on hold)/,
        3,
        "Possible fake delivery notification"
    );

    // =====================================
    // 10. GOVERNMENT AND ELECTRICITY FRAUD
    // =====================================

    check(
        /(electricity|power connection).{0,45}(disconnect|cut|suspend|bill|payment)/,
        3,
        "Possible fake electricity disconnection warning"
    );

    check(
        /(police|court|government|income tax).{0,50}(arrest|fine|penalty|urgent payment|legal action)/,
        3,
        "Possible authority impersonation"
    );

    // =====================================
    // 11. URGENCY AND THREATS
    // =====================================

    check(
        /(immediately|urgent|as soon as possible|right now|within 24 hours|last warning|final warning)/,
        1,
        "Urgent or threatening language"
    );

    check(
        /(account will be blocked|service will be stopped|account will be closed)/,
        2,
        "Threat of account or service suspension"
    );

    // =====================================
    // 12. SUSPICIOUS URL ANALYSIS
    // =====================================

    const urls = email.match(
        /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi
    ) || [];

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "rb.gy",
        "is.gd",
        "shorturl.at"
    ];

    urls.forEach(link => {

        try {

            const cleanLink = link.replace(/[),.!?;]+$/, "");

            const url = new URL(
                cleanLink.startsWith("www.")
                    ? "https://" + cleanLink
                    : cleanLink
            );

            if (url.protocol === "http:") {
                score += 1;
                reasons.push("Link does not use HTTPS");
            }

            if (shorteners.includes(url.hostname.toLowerCase())) {
                score += 3;
                reasons.push("Shortened URL detected");
            }

            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
                score += 4;
                reasons.push("IP address used instead of domain");
            }

            if (url.username || url.password) {
                score += 4;
                reasons.push("Suspicious URL credentials detected");
            }

        } catch (error) {
            score += 2;
            reasons.push("Invalid URL detected");
        }
    });

    // =====================================
    // 13. DANGEROUS ATTACHMENTS
    // =====================================

    check(
        /\.(exe|apk|bat|scr|vbs|js)\b/i,
        3,
        "Potentially dangerous attachment mentioned"
    );

    // =====================================
    // 14. FINAL RISK CALCULATION
    // =====================================

    reasons = [...new Set(reasons)];

    let risk;
    let description;

    if (score >= 6) {
        risk = "HIGH RISK";
        description =
            "Multiple suspicious indicators detected. Do not share OTPs, personal details, click suspicious links, or transfer money.";
    }
    else if (score >= 3) {
        risk = "MEDIUM RISK";
        description =
            "Suspicious patterns detected. Verify the sender independently before taking any action.";
    }
    else {
        risk = "LOW RISK";
        description =
            "No major known scam patterns detected. This does not guarantee that the email is genuine.";
    }

    return {
        score,
        risk,
        description,
        reasons
    };
}













    // Scan button
    detectBtn.addEventListener("click", function () {

        const email = emailInput.value.trim();

        if (!email) {
            resultBox.className = "scan-result medium";
            resultBox.textContent = "Please paste an email first!";
            return;
        }

        const result = analyzeEmail(email);

        resultBox.className =
            "scan-result " + result.risk.split(" ")[0].toLowerCase();

        resultBox.replaceChildren();

        const heading = document.createElement("h3");
        heading.textContent = result.risk;

        const description = document.createElement("p");
        description.textContent = result.description;

        const score = document.createElement("p");
        score.textContent = "Risk Score: " + result.score;

        const details = document.createElement("h4");
        details.textContent = "Detection Details";

        const list = document.createElement("ul");

        if (result.reasons.length === 0) {
            const item = document.createElement("li");
            item.textContent = "No major suspicious patterns found.";
            list.appendChild(item);
        } else {
            result.reasons.forEach(reason => {
                const item = document.createElement("li");
                item.textContent = reason;
                list.appendChild(item);
            });
        }

        resultBox.append(heading, description, score, details, list);
    });

    // Reset button
    resetBtn.addEventListener("click", function () {
        emailInput.value = "";
        resultBox.replaceChildren();
        resultBox.className = "scan-result";
    });

    console.log("NEXSHIELD Email Detection Loaded!");

});