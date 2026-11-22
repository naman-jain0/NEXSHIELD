alert("NEXSHIELD Javascript Connected!");





document.addEventListener("DOMContentLoaded", function () {

    const detectBtn = document.querySelector(".detect-btn");
    const resetBtn = document.querySelector(".reset-btn");
    const messageInput = document.querySelector(".msg");

    if (!detectBtn || !resetBtn || !messageInput) {
        console.error("NEXSHIELD: Required elements not found.");
        return;
    }

    // Automatically create result box
    const resultBox = document.createElement("div");
    resultBox.id = "scan-result";
    resultBox.className = "scan-result";
    resultBox.setAttribute("aria-live", "polite");

    detectBtn.closest(".email-scanner").appendChild(resultBox);

    // MESSAGE ANALYSIS ENGINE
    function analyzeMessage(message) {

        let score = 0;
        let reasons = [];

        const text = message.toLowerCase();

        // 1. OTP and Banking fraud
        const banking = [
            /share.{0,25}otp/,
            /otp.{0,25}(share|send|tell)/,
            /account.{0,30}(blocked|suspended|frozen)/,
            /kyc.{0,30}(update|expire|block)/,
            /(upi pin|atm pin|cvv).{0,30}(share|enter|send)/,
            /bank.{0,30}(password|otp|pin)/
        ];

        banking.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Banking or OTP related suspicious activity");
            }
        });

        // 2. Lottery and Prize fraud
        const lottery = [
            /you have won/,
            /congratulations.{0,40}(prize|winner|lottery)/,
            /lottery.{0,30}(winner|prize)/,
            /claim your (prize|reward)/,
            /free gift.{0,30}(claim|click)/
        ];

        lottery.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Possible fake lottery or prize offer");
            }
        });

        // 3. Payment scams
        const payments = [
            /processing fee/,
            /registration fee/,
            /security fee/,
            /send money immediately/,
            /receive money.{0,30}(upi pin|pin)/,
            /urgent payment/
        ];

        payments.forEach(pattern => {
            if (pattern.test(text)) {
                score += 3;
                reasons.push("Suspicious payment request");
            }
        });

        // 4. Threats and urgency
        const urgency = [
            /immediately/,
            /within 24 hours/,
            /last warning/,
            /electricity.{0,30}(disconnect|cut)/,
            /police.{0,30}(arrest|action)/,
            /account will be blocked/
        ];

        urgency.forEach(pattern => {
            if (pattern.test(text)) {
                score += 1;
                reasons.push("Urgent or threatening language");
            }
        });

        // 5. URL analysis
        const urls = message.match(
            /https?:\/\/[^\s]+|www\.[^\s]+/gi
        ) || [];

        const shorteners = [
            "bit.ly", "tinyurl.com", "t.co",
            "cutt.ly", "rb.gy", "is.gd"
        ];

        urls.forEach(link => {
            try {
                const url = new URL(
                    link.startsWith("www.")
                    ? "https://" + link
                    : link
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
                    reasons.push("Suspicious URL credentials");
                }

            } catch (error) {
                score += 2;
                reasons.push("Invalid URL detected");
            }
        });

        reasons = [...new Set(reasons)];

        let risk;
        let description;

        if (score >= 6) {
            risk = "HIGH RISK";
            description =
                "Multiple scam indicators found. Do not click suspicious links or share personal information.";
        }
        else if (score >= 3) {
            risk = "MEDIUM RISK";
            description =
                "Suspicious patterns found. Verify the sender independently.";
        }
        else {
            risk = "LOW RISK";
            description =
                "No major known scam patterns found. This does not guarantee that the message is genuine.";
        }

        return { score, risk, description, reasons };
    }

    // DISPLAY RESULTS
    detectBtn.addEventListener("click", function () {

        const message = messageInput.value.trim();

        if (!message) {
            resultBox.className = "scan-result medium";
            resultBox.textContent = "Please enter a message first!";
            return;
        }

        const result = analyzeMessage(message);

        resultBox.className = "scan-result " +
            result.risk.split(" ")[0].toLowerCase();

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

    // RESET
    resetBtn.addEventListener("click", function () {
        messageInput.value = "";
        resultBox.replaceChildren();
        resultBox.className = "scan-result";
    });

    console.log("NEXSHIELD Message Detection Loaded!");

});