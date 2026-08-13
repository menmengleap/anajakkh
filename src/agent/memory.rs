//! Session conversation memory.

use serde::{Deserialize, Serialize};

use crate::ai::models::AiMessage;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryEntry {
    User(String),
    Assistant(String),
    System(String),
}

/// Bounded conversation memory for the current session.
#[derive(Debug, Clone, Default)]
pub struct ConversationMemory {
    entries: Vec<MemoryEntry>,
    max_entries: usize,
}

impl ConversationMemory {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 200,
        }
    }

    pub fn push_user(&mut self, content: impl Into<String>) {
        self.push(MemoryEntry::User(content.into()));
    }

    pub fn push_assistant(&mut self, content: impl Into<String>) {
        self.push(MemoryEntry::Assistant(content.into()));
    }

    fn push(&mut self, entry: MemoryEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn last_user(&self) -> Option<&str> {
        self.entries.iter().rev().find_map(|e| match e {
            MemoryEntry::User(text) => Some(text.as_str()),
            _ => None,
        })
    }

    /// Snapshot of all entries (for persistence).
    pub fn entries(&self) -> Vec<MemoryEntry> {
        self.entries.clone()
    }

    /// Restore from a persisted snapshot.
    pub fn from_entries(entries: Vec<MemoryEntry>) -> Self {
        let mut memory = Self::new();
        for entry in entries {
            memory.push(entry);
        }
        memory
    }

    /// Convert to AI messages, prepending the system prompt.
    pub fn to_ai_messages(&self, system: &str) -> Vec<AiMessage> {
        let mut messages = vec![AiMessage::system(system)];
        for entry in &self.entries {
            match entry {
                MemoryEntry::User(text) => messages.push(AiMessage::user(text.clone())),
                MemoryEntry::Assistant(text) => messages.push(AiMessage::assistant(text.clone())),
                MemoryEntry::System(text) => messages.push(AiMessage::system(text.clone())),
            }
        }
        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::models::AiRole;

    #[test]
    fn memory_roundtrip() {
        let mut memory = ConversationMemory::new();
        memory.push_user("scan example.com");
        memory.push_assistant("ok");
        assert_eq!(memory.len(), 2);
        assert_eq!(memory.last_user(), Some("scan example.com"));

        let messages = memory.to_ai_messages("be careful");
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].role, AiRole::System);
        assert_eq!(messages[1].content, "scan example.com");
    }

    #[test]
    fn memory_bounded() {
        let mut memory = ConversationMemory::new();
        for i in 0..(memory.max_entries + 10) {
            memory.push_user(format!("msg {i}"));
        }
        assert_eq!(memory.len(), memory.max_entries);
        assert_eq!(memory.last_user(), Some("msg 209"));
    }
}
