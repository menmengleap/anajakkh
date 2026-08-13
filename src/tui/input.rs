//! Simple text input line with cursor support.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputLine {
    buf: String,
    cursor: usize, // byte index
}

impl InputLine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn text(&self) -> &str {
        &self.buf
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.cursor = 0;
    }

    pub fn set(&mut self, text: &str) {
        self.buf = text.to_string();
        self.cursor = self.buf.len();
    }

    pub fn take(&mut self) -> String {
        let text = std::mem::take(&mut self.buf);
        self.cursor = 0;
        text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn insert_char(&mut self, c: char) {
        self.buf.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        // Find the byte offset of the character just before the cursor.
        let Some((start, _)) = self.buf[..self.cursor].char_indices().next_back() else {
            self.buf.clear();
            self.cursor = 0;
            return;
        };
        self.buf.remove(start);
        self.cursor = start;
    }

    pub fn delete(&mut self) {
        if self.cursor >= self.buf.len() {
            return;
        }
        let next = self.buf[self.cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| self.cursor + i)
            .unwrap_or(self.buf.len());
        self.buf.replace_range(self.cursor..next, "");
    }

    pub fn move_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.buf[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.cursor = prev;
    }

    pub fn move_right(&mut self) {
        if self.cursor >= self.buf.len() {
            return;
        }
        let next = self.buf[self.cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| self.cursor + i)
            .unwrap_or(self.buf.len());
        self.cursor = next;
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.buf.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_backspace() {
        let mut line = InputLine::new();
        line.insert_char('h');
        line.insert_char('i');
        assert_eq!(line.text(), "hi");
        line.backspace();
        assert_eq!(line.text(), "h");
        line.backspace();
        assert!(line.is_empty());
    }

    #[test]
    fn insert_at_cursor() {
        let mut line = InputLine::new();
        line.set("hello");
        line.home();
        line.insert_char('>');
        assert_eq!(line.text(), ">hello");
        // Cursor is after '>'; move right twice lands before the 2nd 'l'.
        line.move_right();
        line.move_right();
        line.delete();
        assert_eq!(line.text(), ">helo");
    }

    #[test]
    fn multibyte_handling() {
        let mut line = InputLine::new();
        line.set("héllo");
        // Cursor at end; move left before 'o', then insert.
        line.move_left();
        line.insert_char('x');
        assert_eq!(line.text(), "héllxo");
        // Move to after 'h' and backspace the 'é'.
        line.home();
        line.move_right();
        line.move_right();
        line.backspace();
        assert_eq!(line.text(), "hllxo");
    }

    #[test]
    fn take_clears() {
        let mut line = InputLine::new();
        line.set("abc");
        assert_eq!(line.take(), "abc");
        assert!(line.is_empty());
    }
}
