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

        let score = 0;
        let reasons = [];

        const text = email.toLowerCase();

        // 1. Password and account theft
        const securityPatterns = [
            /verify.{0,30}(password|account|identity)/,
            /confirm.{0,30}(password|login|account)/,
            /share.{0,20}(otp|password|pin)/,
            /account.{0,30}(suspended|blocked|locked)/,
            /password.{0,30}(expire|reset|confirm)/,
            /login.{0,30}(immediately|required|verify)/
        ];

        securityPatterns.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Possible account or password theft attempt");
            }
        });

        // 2. Prize and lottery fraud
        const lotteryPatterns = [
            /you have won/,
            /congratulations.{0,50}(winner|prize|lottery)/,
            /claim your (prize|reward|money)/,
            /lucky winner/,
            /million dollar prize/,
            /lottery.{0,30}(winner|prize)/
        ];

        lotteryPatterns.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Possible fake lottery or prize email");
            }
        });

        // 3. Payment fraud
        const paymentPatterns = [
            /processing fee/,
            /registration fee/,
            /send money immediately/,
            /payment.{0,30}(urgent|required|pending)/,
            /bank details/,
            /credit card details/
        ];

        paymentPatterns.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Suspicious payment or financial request");
            }
        });

        // 4. Urgency and threats
        const urgencyPatterns = [
            /within 24 hours/,
            /immediately/,
            /final warning/,
            /account will be closed/,
            /limited time/,
            /failure to respond/
        ];

        urgencyPatterns.forEach(pattern => {
            if (pattern.test(text)) {
                score += 1;
                reasons.push("Urgent or threatening language detected");
            }
        });

        // 5. Suspicious links
        const urls = email.match(
            /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi
        ) || [];

        const shorteners = [
            "bit.ly", "tinyurl.com", "t.co",
            "cutt.ly", "rb.gy", "is.gd"
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
                    score += 2;
                    reasons.push("Shortened URL detected");
                }

                if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
                    score += 3;
                    reasons.push("IP address used instead of domain");
                }

                if (url.username || url.password) {
                    score += 3;
                    reasons.push("Suspicious URL credentials detected");
                }

            } catch (error) {
                score += 2;
                reasons.push("Invalid or suspicious URL detected");
            }
        });

        // 6. Suspicious attachment extensions
        const attachmentPatterns = [
            /\.exe\b/,
            /\.apk\b/,
            /\.bat\b/,
            /\.scr\b/,
            /\.js\b/,
            /\.vbs\b/
        ];

        attachmentPatterns.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Potentially dangerous attachment mentioned");
            }
        });

        reasons = [...new Set(reasons)];

        let risk;
        let description;

        if (score >= 6) {
            risk = "HIGH RISK";
            description =
                "Multiple suspicious indicators detected. Do not click links, open unexpected attachments, or share personal information.";
        } else if (score >= 3) {
            risk = "MEDIUM RISK";
            description =
                "Some suspicious patterns detected. Verify the sender through an independent official channel.";
        } else {
            risk = "LOW RISK";
            description =
                "No major known scam patterns detected. This does not guarantee that the email is genuine.";
        }

        return { score, risk, description, reasons };
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