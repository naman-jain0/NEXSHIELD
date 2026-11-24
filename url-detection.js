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
    let domain = "";

    const url = rawURL.trim();

    if (!url) {
        return { error: "Please enter a URL." };
    }

    if (/\s/.test(url)) {
        return { error: "URL contains spaces. Enter a valid URL." };
    }

    let parsedURL;

    try {
        parsedURL = new URL(
            /^https?:\/\//i.test(url) ? url : "https://" + url
        );
    } catch {
        return { error: "Invalid URL. Please check the address." };
    }

    if (!["http:", "https:"].includes(parsedURL.protocol)) {
        return { error: "Unsupported URL protocol." };
    }

    domain = parsedURL.hostname.toLowerCase();

    if (!domain || domain.length > 253) {
        return { error: "Invalid domain name." };
    }

    // Remove trailing dot from hostname
    domain = domain.replace(/\.$/, "");

    // Add each risk indicator only once
    function flag(condition, points, reason) {
        if (condition && !reasons.includes(reason)) {
            score += points;
            reasons.push(reason);
        }
    }

    // 1. HTTP security check
    flag(
        parsedURL.protocol === "http:",
        5,
        "Website does not use HTTPS encryption."
    );

    // 2. IP address detection (IPv4)
    const ipv4 =
        /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

    const isIPv4 = ipv4.test(domain);
    const isIPv6 = domain.includes(":");

    flag(
        isIPv4 || isIPv6,
        25,
        "Website uses an IP address instead of a regular domain."
    );

    // 3. URL shortener detection
    const shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "ow.ly", "is.gd", "buff.ly", "cutt.ly",
        "shorturl.at", "rebrand.ly", "rb.gy",
        "lnkd.in", "tiny.cc"
    ];

    flag(
        shorteners.includes(domain),
        20,
        "URL uses a known link-shortening service. Its final destination is hidden."
    );

    // 4. Punycode detection
    flag(
        domain.split(".").some(part => part.startsWith("xn--")),
        25,
        "Domain contains Punycode encoding, which can be used for lookalike domains."
    );

    // 5. Suspicious domain structure
    const labels = domain.split(".");

    flag(
        labels.length >= 5,
        10,
        "Domain contains an unusually large number of subdomains."
    );

    flag(
        /-{2,}/.test(domain),
        8,
        "Domain contains repeated hyphens."
    );

    // 6. Misleading @ symbol / credentials
    flag(
        parsedURL.username !== "" || parsedURL.password !== "",
        35,
        "URL contains credentials before the hostname. This can hide the real destination."
    );

    // 7. Brand impersonation detection
    const brands = [
        {
            name: "PayPal",
            domains: ["paypal.com"]
        },
        {
            name: "Google",
            domains: ["google.com", "google.co.in"]
        },
        {
            name: "Microsoft",
            domains: ["microsoft.com", "live.com", "outlook.com"]
        },
        {
            name: "Amazon",
            domains: ["amazon.com", "amazon.in"]
        },
        {
            name: "Apple",
            domains: ["apple.com"]
        },
        {
            name: "Facebook",
            domains: ["facebook.com"]
        },
        {
            name: "Instagram",
            domains: ["instagram.com"]
        },
        {
            name: "WhatsApp",
            domains: ["whatsapp.com"]
        },
        {
            name: "SBI",
            domains: ["sbi.co.in", "onlinesbi.sbi"]
        },
        {
            name: "HDFC Bank",
            domains: ["hdfcbank.com"]
        },
        {
            name: "ICICI Bank",
            domains: ["icicibank.com"]
        },
        {
            name: "Axis Bank",
            domains: ["axisbank.com"]
        }
    ];

    for (const brand of brands) {

        const brandText = brand.name
            .toLowerCase()
            .replace(/\s/g, "");

        const hostText = domain.replace(/[^a-z0-9]/g, "");

        const mentionsBrand =
            hostText.includes(brandText) ||
            domain.split(".").some(label =>
                label.includes(brandText)
            );

        const isOfficial = brand.domains.some(
            official =>
                domain === official ||
                domain.endsWith("." + official)
        );

        if (mentionsBrand && !isOfficial) {
            flag(
                true,
                35,
                "Domain may be impersonating " + brand.name + ". Verify the official website."
            );
        }
    }

    // 8. Suspicious words in hostname only
    const suspiciousHostWords = [
        "secure-login",
        "account-verify",
        "verify-account",
        "banking-update",
        "password-reset",
        "free-gift",
        "claim-prize"
    ];

    flag(
        suspiciousHostWords.some(word => domain.includes(word)),
        15,
        "Hostname contains a suspicious combination of words."
    );

    // 9. Suspicious URL path
    const path = parsedURL.pathname.toLowerCase();

    flag(
        /\/(login|signin|verify|webscr|credential|password-reset)(\/|$)/i.test(path),
        5,
        "URL path contains a login or verification-related keyword."
    );

    // 10. Suspicious redirect parameters
    const redirectParams = [
        "redirect", "redirect_url", "return_url",
        "next", "continue", "destination"
    ];

    let hasExternalRedirect = false;

    for (const param of redirectParams) {
        const value = parsedURL.searchParams.get(param);

        if (value && /^https?:\/\//i.test(value)) {
            try {
                const target = new URL(value);

                if (target.hostname !== domain) {
                    hasExternalRedirect = true;
                }
            } catch {}
        }
    }

    flag(
        hasExternalRedirect,
        15,
        "URL contains a parameter redirecting visitors to another website."
    );

    // 11. Unusual port
    flag(
        parsedURL.port !== "" &&
        !["80", "443"].includes(parsedURL.port),
        10,
        "Website uses an unusual network port."
    );

    // 12. Risky download extension
    flag(
        /\.(apk|exe|scr|bat|cmd|msi|js|jar)$/i.test(path),
        20,
        "URL points to a potentially risky executable or application file."
    );

    // 13. Excessively long URL
    flag(
        url.length > 200,
        5,
        "URL is unusually long and should be checked carefully."
    );

    // 14. Excessive encoding
    const encodedCount = (url.match(/%[0-9a-f]{2}/gi) || []).length;

    flag(
        encodedCount >= 8,
        8,
        "URL contains an unusually high number of encoded characters."
    );

    // Final score
    score = Math.min(score, 100);

    let risk;
    let description;

    if (score >= 60) {
        risk = "HIGH";
        description = "Multiple strong suspicious indicators were detected.";
    } else if (score >= 25) {
        risk = "MEDIUM";
        description = "Several suspicious indicators were detected.";
    } else if (score >= 10) {
        risk = "LOW";
        description = "Some unusual characteristics need verification.";
    } else {
        risk = "SAFE";
        description = "No major suspicious patterns were detected by this scanner.";
    }

    if (reasons.length === 0) {
        reasons.push("No suspicious patterns were detected in the URL structure.");
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