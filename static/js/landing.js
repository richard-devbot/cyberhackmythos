() => {
    // Landing page toggle logic
    const landingPage = document.getElementById('landing-page-container');
    const chatbot = document.getElementById('chatbot');
    const msgInput = document.querySelector('#input-row textarea, #input-row input[type="text"]');

    if (!landingPage || !chatbot) return;

    function toggleLanding() {
        // Check if chatbot has any messages
        const messages = chatbot.querySelectorAll('[data-testid="bot"], [data-testid="user"], [class*="message"]');
        const hasMessages = messages.length > 0;

        // Also check for empty state indicators
        const emptyState = chatbot.querySelector('.empty-state, .placeholder, [class*="empty"]');
        const chatColumn = document.getElementById('chat-column');

        if (hasMessages && !emptyState) {
            landingPage.classList.add('hidden');
            if (chatColumn) chatColumn.classList.remove('landing-active');
        } else {
            landingPage.classList.remove('hidden');
            if (chatColumn) chatColumn.classList.add('landing-active');
        }
    }

    // Initial check
    toggleLanding();

    // Set up mutation observer to watch for chat changes
    const observer = new MutationObserver((mutations) => {
        let shouldToggle = false;
        for (const mutation of mutations) {
            if (mutation.type === 'childList' || mutation.type === 'subtree') {
                shouldToggle = true;
                break;
            }
        }
        if (shouldToggle) {
            // Debounce the toggle check
            clearTimeout(window._landingToggleTimeout);
            window._landingToggleTimeout = setTimeout(toggleLanding, 100);
        }
    });

    observer.observe(chatbot, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class']
    });

    // Also watch for the input area to handle new chat creation
    const inputRow = document.getElementById('input-row');
    if (inputRow) {
        observer.observe(inputRow, {
            childList: true,
            subtree: true
        });
    }

    // Click on landing prompt to focus input
    const landingPrompt = document.querySelector('.landing-prompt');
    if (landingPrompt && msgInput) {
        landingPrompt.addEventListener('click', () => {
            msgInput.focus();
            msgInput.click();
        });
    }

    // Store reference for cleanup
    window._landingPageObserver = observer;
    window._landingPage = landingPage;
}