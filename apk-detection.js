document.addEventListener("DOMContentLoaded", function () {

    const apkInput = document.querySelector("#apk-file");
    const apkForm = document.querySelector(".APK-container form");
    const container = document.querySelector(".APK-container");

    if (!apkInput || !apkForm || !container) {
        console.error("NEXSHIELD: APK elements not found!");
        return;
    }

    // Create result box
    const resultBox = document.createElement("div");
    resultBox.className = "scan-result";
    resultBox.setAttribute("aria-live", "polite");
    container.appendChild(resultBox);

    // Display result safely
    function showResult(title, messages, type) {

        resultBox.className = "scan-result " + type;
        resultBox.replaceChildren();

        const heading = document.createElement("h3");
        heading.textContent = title;
        resultBox.appendChild(heading);

        messages.forEach(message => {
            const p = document.createElement("p");
            p.textContent = message;
            resultBox.appendChild(p);
        });
    }

    // Calculate SHA-256 hash
    async function calculateHash(file) {

        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest(
            "SHA-256",
            buffer
        );

        return Array.from(new Uint8Array(hashBuffer))
            .map(byte => byte.toString(16).padStart(2, "0"))
            .join("");
    }

    // APK scan
    apkForm.addEventListener("submit", async function (event) {

        event.preventDefault();

        const file = apkInput.files[0];

        if (!file) {
            showResult(
                "NO FILE SELECTED",
                ["Please select an APK file first."],
                "medium"
            );
            return;
        }

        // Check file extension
        if (!file.name.toLowerCase().endsWith(".apk")) {
            showResult(
                "INVALID FILE",
                ["Please upload a file with .apk extension."],
                "high"
            );
            return;
        }

        showResult(
            "ANALYZING APK...",
            ["Checking file format and calculating SHA-256 hash. Please wait."],
            "medium"
        );

        try {

            // Check APK ZIP signature
            const header = await file.slice(0, 4).arrayBuffer();
            const bytes = new Uint8Array(header);

            const validZip =
                bytes.length === 4 &&
                bytes[0] === 0x50 &&
                bytes[1] === 0x4B &&
                (
                    (bytes[2] === 0x03 && bytes[3] === 0x04) ||
                    (bytes[2] === 0x05 && bytes[3] === 0x06) ||
                    (bytes[2] === 0x07 && bytes[3] === 0x08)
                );

            if (!validZip) {
                showResult(
                    "INVALID APK FORMAT",
                    [
                        "The file has an APK extension but does not have a recognized ZIP signature.",
                        "The file may be corrupted or incorrectly renamed."
                    ],
                    "high"
                );
                return;
            }

            // Calculate hash
            const hash = await calculateHash(file);

            const sizeMB = (file.size / (1024 * 1024)).toFixed(2);

            const messages = [
                "File Name: " + file.name,
                "File Size: " + sizeMB + " MB",
                "File Format: ZIP signature detected",
                "SHA-256: " + hash,
                "Basic format validation completed.",
                "No malware verdict is available from this browser-only check."
            ];

            showResult(
                "FILE FORMAT CHECK PASSED",
                messages,
                "low"
            );

        } catch (error) {

            console.error(error);

            showResult(
                "ANALYSIS FAILED",
                [
                    "The browser could not analyze this file.",
                    "Try again using a local development server such as Live Server."
                ],
                "high"
            );
        }
    });

    // Reset when another file is selected
    apkInput.addEventListener("change", function () {
        resultBox.replaceChildren();
        resultBox.className = "scan-result";
    });

    console.log("NEXSHIELD APK Detection Loaded!");

});