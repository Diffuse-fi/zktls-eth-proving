use std::time::Instant;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Default, Serialize, Clone)]
pub struct Timings {
    pub total_ms: f64,
    pub stages: HashMap<String, f64>,
}

pub struct Lap {
    name: String,
    start: Instant,
}

impl Lap {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start: Instant::now(),
        }
    }

    pub fn stop(self, timings: &mut Timings) {
        let duration_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        timings.stages.insert(self.name, duration_ms);
    }
}