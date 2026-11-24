document.addEventListener("DOMContentLoaded", function () {

    const scanBtn = document.querySelector(".detect-btn");
    const resetBtn = document.querySelector(".reset-btn");

    // URL input: supports common input selectors
    const urlInput =
        document.querySelector("#url-input") ||
        document.querySelector("#url") ||
        document.querySelector(".url-input") ||
        document.querySelector(".url");

    const scanner =
        document.querySelector(".email-scanner") ||
        document.querySelector(".url-scanner") ||
        document.querySelector("main");

    if (!scanBtn || !urlInput || !scanner) {
        console.error("NEXSHIELD URL Scanner: Required HTML elements not found.");
        return;
    }

    // Create result box
    let resultBox = document.querySelector(".scan-result");

    if (!resultBox) {
        resultBox = document.createElement("div");
        resultBox.className = "scan-result";
        scanner.appendChild(resultBox);
    }

    function analyzeURL(rawURL) {

        let score = 0;
        let reasons = [];
        let domain = "Unknown";
        let parsedURL;

        const url = rawURL.trim();

        // 1. URL validation
        if (!url) {
            return {
                error: "Please enter a URL."
            };
        }

        if (/\s/.test(url)) {
            return {
                error: "URL contains spaces. Please enter a valid URL."
            };
        }

        let normalizedURL = url;

        if (!/^https?:\/\//i.test(normalizedURL)) {
            normalizedURL = "https://" + normalizedURL;
        }

        try {
            parsedURL = new URL(normalizedURL);
        } catch (error) {
            return {
                error: "Invalid URL. Please enter a valid website address."
            };
        }

        if (!["http:", "https:"].includes(parsedURL.protocol)) {
            return {
                error: "Only HTTP and HTTPS URLs are supported."
            };
        }

        domain = parsedURL.hostname.toLowerCase();

        if (!domain || !domain.includes(".")) {
            return {
                error: "Invalid domain name."
            };
        }

        // Helper for adding risk
        function flag(condition, points, reason) {
            if (condition) {
                score += points;
                reasons.push(reason);
            }
        }

        // 2. HTTP instead of HTTPS
        flag(
            parsedURL.protocol === "http:",
            10,
            "Website is using HTTP instead of secure HTTPS."
        );

        // 3. IP address based URL
        const ipv4Pattern =
            /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

        const isIP = ipv4Pattern.test(domain);

        flag(
            isIP,
            30,
            "Website uses an IP address instead of a normal domain name."
        );

        // 4. URL shorteners
        const shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "cutt.ly",
            "shorturl.at",
            "rebrand.ly"
        ];

        const isShortener = shorteners.includes(domain);

        flag(
            isShortener,
            20,
            "URL uses a shortened link which hides the final destination."
        );

        // 5. Suspicious words in URL
        const suspiciousWords = [
            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "update",
            "password",
            "banking",
            "wallet",
            "free",
            "bonus",
            "prize",
            "claim",
            "gift",
            "reward",
            "confirm"
        ];

        const urlText = (
            parsedURL.hostname +
            parsedURL.pathname +
            parsedURL.search
        ).toLowerCase();

        const foundWords = suspiciousWords.filter(word =>
            urlText.includes(word)
        );

        if (foundWords.length > 0) {
            flag(
                true,
                Math.min(foundWords.length * 5, 15),
                "Suspicious keywords found: " + foundWords.join(", ")
            );
        }

        // 6. Excessive subdomains
        const domainParts = domain.split(".");

        flag(
            domainParts.length >= 5,
            15,
            "URL contains an unusually large number of subdomains."
        );

        // 7. Misleading @ symbol
        flag(
            parsedURL.username !== "" || parsedURL.password !== "",
            25,
            "URL contains user credentials before the domain, which may be misleading."
        );

        // 8. Suspicious domain patterns
        flag(
            /xn--/i.test(domain),
            20,
            "Domain uses Punycode encoding and may imitate another website."
        );

        flag(
            /-{2,}/.test(domain),
            10,
            "Domain contains repeated hyphens."
        );

        // 9. Very long URL
        flag(
            url.length > 150,
            10,
            "URL is unusually long."
        );

        // 10. Suspicious file extensions
        flag(
            /\.(apk|exe|scr|bat|cmd|msi|zip)$/i.test(parsedURL.pathname),
            20,
            "URL points to a potentially risky downloadable file."
        );

        // 11. Final score
        score = Math.min(score, 100);

        let risk = "SAFE";
        let description = "No obvious suspicious patterns were detected.";

        if (score >= 60) {
            risk = "HIGH";
            description = "This URL contains multiple suspicious indicators.";
        } else if (score >= 30) {
            risk = "MEDIUM";
            description = "This URL has suspicious characteristics. Be careful.";
        } else if (score >= 10) {
            risk = "LOW";
            description = "Some unusual characteristics were detected.";
        }

        if (reasons.length === 0) {
            reasons.push("No suspicious URL patterns were detected by this scanner.");
        }

        return {
            domain,
            score,
            risk,
            description,
            reasons
        };
    }

    // Display results
    function displayResult(result) {

        if (result.error) {
            resultBox.innerHTML = `
                <h3>URL Validation Failed</h3>
                <p>${result.error}</p>
            `;
            resultBox.style.display = "block";
            return;
        }

        const riskColor = {
            SAFE: "#00d68f",
            LOW: "#8bc34a",
            MEDIUM: "#ffb020",
            HIGH: "#ff4d4d"
        };

        const reasonsHTML = result.reasons
            .map(reason => `<li>${reason}</li>`)
            .join("");

        resultBox.innerHTML = `
            <h3>URL Scan Result</h3>

            <p><strong>Domain:</strong> ${result.domain}</p>

            <p>
                <strong>Risk Level:</strong>
                <span style="color:${riskColor[result.risk]};font-weight:bold;">
                    ${result.risk} RISK
                </span>
            </p>

            <p><strong>Risk Score:</strong> ${result.score}/100</p>

            <p>${result.description}</p>

            <h4>Risk Analysis</h4>
            <ul>${reasonsHTML}</ul>

            <h4>Safety Recommendation</h4>
            <p>
                ${
                    result.risk === "HIGH"
                    ? "Avoid opening this link. Do not enter passwords, OTPs or payment details."
                    : result.risk === "MEDIUM"
                    ? "Do not enter sensitive information. Verify the website through its official source."
                    : result.risk === "LOW"
                    ? "Proceed carefully. Check the website address before sharing personal information."
                    : "Always verify the domain before entering sensitive information."
                }
            </p>

            <p style="font-size:12px;opacity:0.7;">
                Note: This is a rule-based analysis, not a guarantee that a website is safe.
            </p>
        `;

        resultBox.style.display = "block";
    }

    // Scan button
    scanBtn.addEventListener("click", function () {
        const result = analyzeURL(urlInput.value);
        displayResult(result);
    });

    // Reset button
    if (resetBtn) {
        resetBtn.addEventListener("click", function () {
            resultBox.innerHTML = "";
            resultBox.style.display = "none";
        });
    }

});