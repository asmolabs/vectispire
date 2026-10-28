//! `ListWindow`: one page of a list route, cut from what the caller sees — a limit and an offset that is a
//! multiple of it.

/// The most rows one page carries.
pub const MAX_LIMIT: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListWindow {
    pub limit: i64,
    pub offset: i64,
}

impl ListWindow {
    /// The compact constructor's checks, with its sentences.
    pub fn new(limit: i64, offset: i64) -> Result<ListWindow, String> {
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(format!("The limit is between 1 and {MAX_LIMIT}."));
        }
        if offset < 0 || offset.checked_rem(limit) != Some(0) {
            return Err("The offset is zero or a multiple of the limit.".to_owned());
        }
        Ok(ListWindow { limit, offset })
    }

    /// `requested`: no limit and no offset is the whole list, as before paging existed; an offset without a limit
    /// is refused rather than ignored.
    pub fn requested(limit: Option<i64>, offset: Option<i64>) -> Result<Option<ListWindow>, String> {
        match limit {
            None if offset.is_some() => {
                Err("An offset is read with a limit; without either, the whole list is answered.".to_owned())
            }
            None => Ok(None),
            Some(limit) => ListWindow::new(limit, offset.unwrap_or(0)).map(Some),
        }
    }

    /// `of`: the page's rows; past the end, none.
    pub fn of<T: Clone>(&self, rows: &[T]) -> Vec<T> {
        let (Ok(start), Ok(limit)) = (usize::try_from(self.offset), usize::try_from(self.limit)) else {
            return Vec::new();
        };
        rows.iter().skip(start).take(limit).cloned().collect()
    }
}
