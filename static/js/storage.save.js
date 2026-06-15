(stateJson) => {
    const state = JSON.parse(stateJson);
    const titles = {};

    for (const conv of (state.conversations || [])) {
        titles[conv.key] = { label: conv.label, last_updated: conv.last_updated || 0 };
        const ctx = (state.conversation_contexts || {})[conv.key];
        if (ctx !== undefined) {
            localStorage.setItem("chat_id_" + conv.key, JSON.stringify(ctx));
        }
    }

    // Remove stale chat_id_* keys that are no longer in conversations
    const validIds = new Set(Object.keys(titles));
    for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith("chat_id_")) {
            const id = k.slice("chat_id_".length);
            if (!validIds.has(id)) {
                localStorage.removeItem(k);
                i--;  // adjust index after removal
            }
        }
    }

    localStorage.setItem("titles", JSON.stringify(titles));
    return stateJson;
}