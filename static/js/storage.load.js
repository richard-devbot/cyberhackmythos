(_) => {
    const titles = JSON.parse(localStorage.getItem("titles") || "{}");
    const conversations = [];
    const conversation_contexts = {};

    for (const [id, data] of Object.entries(titles)) {
        const raw = localStorage.getItem("chat_id_" + id);
        if (raw) {
            const label = typeof data === 'string' ? data : data.label;
            const last_updated = typeof data === 'string' ? 0 : (data.last_updated || 0);
            conversations.push({ key: id, label: label, last_updated: last_updated });
            conversation_contexts[id] = JSON.parse(raw);
        }
    }

    // Sort newest first
    conversations.sort((a, b) => (b.last_updated || 0) - (a.last_updated || 0));

    return JSON.stringify({ conversations, conversation_contexts });
}