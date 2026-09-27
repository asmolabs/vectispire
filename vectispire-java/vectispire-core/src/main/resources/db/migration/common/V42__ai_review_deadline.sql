-- A model review is recorded when it is asked for, and settled once the model has answered.
--
-- The row used to be written once, after the call, by a transaction held open around a request
-- that may take five minutes. It is written with the status `running` now, in a transaction of its
-- own; the call runs with none open; a second transaction writes what came back. A process that
-- stops in between leaves a row saying `running`, and `deadline_at` is when nothing can be waiting
-- for it any more — the model's timeout and a margin, counted from the request. Past it the row reads
-- as failed, and the hourly sweep writes it so.
--
-- Null on every row already stored: all of them are settled, and a settled review has no deadline.
--
-- Written once, in common: an added nullable column.

alter table t_ai_review_result add column deadline_at ${ts};
